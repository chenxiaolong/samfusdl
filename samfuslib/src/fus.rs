use crate::{
    crypto::{CryptoError, FusAes256, FusKeys},
    version::{FwVersion, ParseFwVersionError},
};

use std::{
    borrow::Cow,
    convert::TryInto,
    fmt,
    ops::Range,
    path::Path,
    str,
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD,
};
use bytes::Bytes;
use futures_core::Stream;
use log::debug;
use reqwest::{
    header::{AUTHORIZATION, CONTENT_LENGTH, RANGE},
    RequestBuilder, Response,
    StatusCode,
};
use thiserror::Error;
use xmltree::{Element, XMLNode};

const FOTA_BASE_URL: &str = "https://fota-cloud-dn.ospserver.net";
const FUS_BASE_URL: &str = "https://neofussvr.sslcs.cdngc.net";
const DOWNLOAD_BASE_URL: &str = "http://cloud-neofussvr.sslcs.cdngc.net";
const NON_UTF8_MSG: &str = "[Non-UTF-8 data]";

fn to_utf8_or_error_string(data: &[u8]) -> &str {
    str::from_utf8(data).unwrap_or(NON_UTF8_MSG)
}

#[derive(Debug, Error)]
pub enum FusError {
    #[error("Server did not provide a nonce value")]
    NonceNotFound,
    #[error("Nonce is not exactly 16 bytes")]
    NonceInvalidSize,
    #[error("The latest firmware could not be found")]
    FirmwareNotFound,
    #[error("Expected HTTP {0}, but got HTTP {1}")]
    BadHttpResponse(StatusCode, StatusCode),
    #[error("Received unsuccessful FUS response: {0}")]
    FusBadResponse(String),
    #[error("Could not find field '{0}' in FUS response")]
    FusMissingField(String),
    #[error("Could not parse the value for field '{0}': '{1}'")]
    FusBadField(String, String),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Failed to parse version string: {0}")]
    VersionParseError(#[from] ParseFwVersionError),
    #[error("Failed to decode base64 data: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("XML parse error: {0}")]
    XmlParseError(#[from] xmltree::ParseError),
    #[error("XML error: {0}")]
    XmlError(#[from] xmltree::Error),
}

/// A type representing the Authorization field for FUS requests.
#[derive(Debug)]
struct Authorization {
    pub nonce: String,
    pub signature: String,
    pub nc: String,
    pub type_: String,
    pub realm: String,
    pub newauth: bool,
}

impl Authorization {
    /// Construct a new instance with no component fields set and the new auth
    /// mechanism enabled. Same as [`Self::default()`].
    fn new() -> Self {
        Self::default()
    }

    /// Construct a new instance with the specified nonce signature and the new
    /// auth mechanism enabled.
    fn with_signature(signature: &str) -> Self {
        Self {
            nonce: Default::default(),
            signature: signature.to_string(),
            nc: Default::default(),
            type_: Default::default(),
            realm: Default::default(),
            newauth: true,
        }
    }
}

impl Default for Authorization {
    fn default() -> Self {
        Self {
            nonce: Default::default(),
            signature: Default::default(),
            nc: Default::default(),
            type_: Default::default(),
            realm: Default::default(),
            // We do not support the legacy auth mechanism (unencrypted nonces)
            // so make the new mechanism the default
            newauth: true,
        }
    }
}

impl fmt::Display for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"{}\", type=\"{}\", realm=\"{}\", newauth=\"{}\"",
            self.nonce,
            self.signature,
            self.nc,
            self.type_,
            self.realm,
            u8::from(self.newauth),
        )
    }
}

#[derive(Clone, Copy)]
enum LogicCheckType<'a> {
    Data(&'a [u8]),
    Filename(&'a str),
}

/// A type representing a FUS nonce value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Nonce {
    // The official implementation tries to convert the AES flexible key from
    // the platform string encoding to UTF-8 into a 33-byte NULL-terminated
    // buffer. It never checks the return value, but relies on the data being
    // written to the buffer. We can reasonably assume that the key is 32 bytes,
    // meaning the nonce must be at most 16 bytes. Many other functions, such as
    // one for computing the <LOGIC_CHECK> value expect the nonce to be at least
    // 16 bytes, so we can conclude that it must be exactly 16 bytes.
    data: [u8; 16],
}

impl Nonce {
    /// Create instance from a byte slice containing the nonce.
    /// [`FusError::InvalidNonceSize`] is returned if the slice is not 16 bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, FusError> {
        Ok(Self {
            data: data.try_into().map_err(|_| FusError::NonceInvalidSize)?,
        })
    }

    /// Get byte slice containing the nonce. The slice is guaranteed to always
    /// be 16 bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Create instance from a fixed-key-encrypted nonce value.
    pub fn from_encrypted(keys: &FusKeys, data: &[u8]) -> Result<Self, FusError> {
        let decoded = STANDARD.decode(data)?;
        let plaintext = FusAes256::new(&keys.fixed_key).decrypt(&decoded)?;
        Self::from_slice(&plaintext)
    }

    /// Convert nonce to fixed-key-encrypted nonce.
    pub fn to_encrypted(self, keys: &FusKeys) -> String {
        STANDARD.encode(FusAes256::new(&keys.fixed_key).encrypt(&self.data))
    }

    /// Get the nonce signature to be used in the Authorization header for FUS
    /// requests.
    fn to_signature(self, keys: &FusKeys) -> String {
        let key = keys.get_flexible_key(self.as_slice());
        let ciphertext = FusAes256::new(&key).encrypt(self.as_slice());

        STANDARD.encode(ciphertext)
    }

    /// Get full Authorization header value containing the nonce signature.
    fn to_authorization(self, keys: &FusKeys) -> Authorization {
        Authorization::with_signature(&self.to_signature(keys))
    }

    /// Get the scrambled nonce value to be used in the `<LOGIC_CHECK>` XML tag
    /// of FUS requests.
    fn to_logic_check(self, lc_type: LogicCheckType) -> String {
        match lc_type {
            LogicCheckType::Data(data) => {
                if data.is_empty() {
                    return String::new();
                }

                self.as_slice().iter()
                    .map(|c| data[(*c as usize & 0xf) % data.len()] as char)
                    .collect()
            }
            LogicCheckType::Filename(filename) => {
                let mut data = filename.as_bytes();

                if let Some(n) = data.iter().position(|x| *x == b'.') {
                    data = &data[..n];
                }
                if data.len() > 16 {
                    data = &data[data.len() - 16..];
                }

                self.to_logic_check(LogicCheckType::Data(data))
            }
        }
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally keep error text at 16 bytes
        write!(f, "{}", to_utf8_or_error_string(&self.data))
    }
}

#[derive(Debug)]
pub struct FirmwareInfo {
    /// Firmware version
    pub version: FwVersion,
    /// Friendly version name
    pub version_name: String,
    /// Firmware OS/platform
    pub platform: String,
    /// Model number
    pub model: String,
    /// Human-readable model/marketing name
    pub model_name: String,
    /// [Unknown] Model type number
    pub model_type: u8,
    /// Region code
    pub region: String,
    /// Firmware download path component
    pub path: String,
    /// Firmware filename. Guaranteed to have no directory component
    pub filename: String,
    /// Firmware size in bytes
    pub size: u64,
    /// Firmware CRC32 checksum
    pub crc: u32,
    /// Firmware modification date
    pub last_modified: String, // TODO: date type?
    /// [Home] Whether the new encryption logic is used
    pub logic_option_home: bool,
    /// [Factory] Whether the new encryption logic is used
    pub logic_option_factory: bool,
    /// [home] Logic value for decryption
    pub logic_value_home: String,
    /// [Factory] Logic value for decryption
    pub logic_value_factory: String,
    /// Whether the binary is a factory binary
    pub binary_nature: bool,
}

impl FirmwareInfo {
    /// Compute the encryption key for the firmware. This function automatically
    /// handles factory vs home firmware and v2 vs v4 keys.
    pub fn encryption_key(&self) -> Result<[u8; 16], FusError> {
        let (new_logic, logic_value) = if self.binary_nature {
            (self.logic_option_factory, &self.logic_value_factory)
        } else {
            (self.logic_option_home, &self.logic_value_home)
        };

        let key = if new_logic {
            Nonce::from_slice(logic_value.as_bytes())?
                .to_logic_check(LogicCheckType::Data(self.version.to_string().as_bytes()))
        } else {
            format!("{}:{}:{}", self.region, self.model, self.version)
        };

        let digest = md5::compute(key.as_bytes());
        Ok(digest.into())
    }

    /// Split the filename into (target filename, enc extension). If the server-
    /// provided filename does not have an enc extension, the extension is set
    /// to "enc".
    pub fn split_filename(&self) -> (String, String) {
        let p = Path::new(&self.filename);
        let stem = p.file_stem();
        let ext = p.extension();

        if let (Some(s), Some(e)) = (stem, ext) {
            // Cannot panic
            let e_str = e.to_str().unwrap();
            if e_str.starts_with("enc") {
                // Cannot panic
                let s_str = s.to_str().unwrap();
                return (s_str.to_owned(), e_str.to_owned());
            }
        }

        (self.filename.clone(), "enc".to_owned())
    }
}

/// Builder type for creating FUS clients with non-default behavior.
#[derive(Clone)]
pub struct FusClientBuilder {
    keys: FusKeys,
    ignore_tls_validation: bool,
}

impl FusClientBuilder {
    pub fn new(keys: FusKeys) -> Self {
        Self {
            keys,
            ignore_tls_validation: false,
        }
    }

    /// Ignore TLS certificate validation when performing HTTPS requests. By
    /// default, TLS certificate validation is enabled.
    pub fn ignore_tls_validation(mut self, value: bool) -> Self {
        self.ignore_tls_validation = value;
        self
    }

    /// Build the FUS client with the current options. This function fails if
    /// the TLS backend fails to initialize.
    pub fn build(&self) -> Result<FusClient, FusError> {
        FusClient::with_options(self)
    }
}

/// Type for interacting with the FUS service.
pub struct FusClient {
    client: reqwest::Client,
    keys: FusKeys,
    nonce: Option<Nonce>,
}

impl FusClient {
    /// Build a new FUS client object with the options from the specified
    /// builder.
    fn with_options(options: &FusClientBuilder) -> Result<Self, FusError> {
        debug!("TLS validation enabled: {}", !options.ignore_tls_validation);

        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(options.ignore_tls_validation)
            .cookie_store(true)
            .referer(false)
            .build()?;

        Ok(Self {
            client,
            keys: options.keys.clone(),
            nonce: None,
        })
    }

    /// Get the latest available firmware version for a given model number and
    /// CSC region code.
    pub async fn get_latest_version(&self, model: &str, region: &str) -> Result<FwVersion, FusError> {
        let url = format!("{FOTA_BASE_URL}/firmware/{region}/{model}/version.xml");
        debug!("FOTA URL: {url}");

        let r = self.client.get(&url).send().await?;
        match r.error_for_status_ref() {
            Ok(_) => {}
            Err(e) => {
                // The FOTA server returns 403 when the page is not found
                return if e.status() == Some(reqwest::StatusCode::FORBIDDEN) {
                    Err(FusError::FirmwareNotFound)
                } else {
                    Err(e.into())
                }
            }
        }

        let data = r.bytes().await?;
        debug!("FOTA response: {:?}", to_utf8_or_error_string(&data));

        let root = Element::parse(data.as_ref())?;
        let version = Self::get_elem_text(&root, &["firmware", "version", "latest"])
            .ok_or(FusError::FirmwareNotFound)?;

        Ok(version.parse()?)
    }

    /// Return an error if the FUS response did not return HTTP 200. If a NONCE
    /// header exists, regardless of the status code, then it is saved for use
    /// with the next request.
    fn check_fus_response(&mut self, response: &Response) -> Result<(), FusError> {
        self.nonce = response.headers().get("NONCE")
            .and_then(|x| Nonce::from_encrypted(&self.keys, x.as_bytes()).ok());

        response.error_for_status_ref()?;
        Ok(())
    }

    /// Generate nonce to use for authentication in further requests. The same
    /// nonce will be returned until it is consumed by a FUS request.
    async fn ensure_nonce(&mut self) -> Result<Nonce, FusError> {
        if let Some(nonce) = self.nonce {
            return Ok(nonce);
        }

        let url = format!("{FUS_BASE_URL}/NF_DownloadGenerateNonce.do");
        debug!("Requesting nonce from: {url}");

        let r = self.client.post(&url)
            .header(AUTHORIZATION, Authorization::new().to_string())
            .header(CONTENT_LENGTH, 0)
            .send()
            .await?;
        self.check_fus_response(&r)?;
        self.nonce.ok_or(FusError::NonceNotFound)
    }

    /// Perform FUS HTTP request, automatically handling the insertion of the
    /// Authorization header and the persisting of the NONCE response header.
    async fn execute_fus_request(
        &mut self,
        request: RequestBuilder,
        auth_include_nonce: bool,
    ) -> Result<Response, FusError> {
        let nonce = self.ensure_nonce().await?;

        let mut auth = nonce.to_authorization(&self.keys);
        if auth_include_nonce {
            auth.nonce = nonce.to_encrypted(&self.keys);
        }

        let r = request
            .header(AUTHORIZATION, auth.to_string())
            .send()
            .await?;
        self.check_fus_response(&r)?;

        Ok(r)
    }

    /// Perform FUS HTTP request, parsing the response body as XML and
    /// interpreting the FUS status code.
    async fn execute_fus_xml_request(
        &mut self,
        url: &str,
        body: &Element,
        auth_include_nonce: bool,
    ) -> Result<Element, FusError> {
        debug!("FUS URL: {url}");

        let mut buf = vec![];
        body.write(&mut buf)?;

        debug!("FUS request: {:?}", to_utf8_or_error_string(&buf));

        let request = self.client.post(url).body(buf);
        let r = self.execute_fus_request(request, auth_include_nonce).await?;
        let data = r.bytes().await?;

        debug!("FUS response: {:?}", to_utf8_or_error_string(&data));

        let root = Element::parse(data.as_ref())?;

        // HTTP 200, but there might still be a FUS error
        let status = Self::get_elem_text(&root, &["FUSBody", "Results", "Status"])
            .ok_or_else(|| FusError::FusBadResponse("Missing FUS status field".to_owned()))?;

        if status != "200" {
            return Err(FusError::FusBadResponse(status.to_string()));
        }

        Ok(root)
    }

    /// Get information about a firmware version for a given model and region.
    pub async fn get_firmware_info(
        &mut self,
        model: &str,
        region: &str,
        version: &FwVersion,
        factory: bool,
    ) -> Result<FirmwareInfo, FusError> {
        let nonce = self.ensure_nonce().await?;
        let req_root = Self::create_binary_inform_elem(model, region, version, nonce, factory);

        let url = format!("{FUS_BASE_URL}/NF_DownloadBinaryInform.do");
        let resp_root = self.execute_fus_xml_request(&url, &req_root, false).await?;

        macro_rules! get_value {
            ($var:expr, $name:expr) => {
                Self::get_fus_field($var, $name)
                    .ok_or(FusError::FusMissingField($name.to_owned()))?
            }
        }
        macro_rules! get_string {
            ($var:expr, $name:expr) => {
                get_value!($var, $name).to_string()
            }
        }
        macro_rules! get_parsed {
            ($var:expr, $name:expr) => {
                {
                    let value = get_value!($var, $name);
                    value.parse().map_err(|_| FusError::FusBadField(
                        $name.to_owned(), value.to_string()))?
                }
            }
        }

        let binary_name = get_string!(&resp_root, "BINARY_NAME");
        let filename = Path::new(&binary_name)
            .file_name()
            .ok_or_else(|| FusError::FusBadField("BINARY_NAME".to_owned(), binary_name.clone()))?
            .to_str()
            .unwrap() // Cannot panic
            .to_owned();

        Ok(FirmwareInfo {
            version: get_parsed!(&resp_root, "CURRENT_DISPLAY_VERSION"),
            version_name: get_string!(&resp_root, "CURRENT_OS_VERSION"),
            platform: get_string!(&resp_root, "DEVICE_PLATFORM"),
            model: get_string!(&resp_root, "DEVICE_MODEL_NAME"),
            model_name: get_string!(&resp_root, "DEVICE_MODEL_DISPLAYNAME"),
            model_type: get_parsed!(&resp_root, "DEVICE_MODEL_TYPE"),
            region: get_string!(&resp_root, "DEVICE_LOCAL_CODE"),
            path: get_string!(&resp_root, "MODEL_PATH"),
            filename,
            size: get_parsed!(&resp_root, "BINARY_BYTE_SIZE"),
            crc: get_parsed!(&resp_root, "BINARY_CRC"),
            last_modified: get_string!(&resp_root, "LAST_MODIFIED"), // TODO (20200226162005)
            logic_option_home: get_value!(&resp_root, "LOGIC_OPTION_HOME") == "1",
            logic_option_factory: get_value!(&resp_root, "LOGIC_OPTION_FACTORY") == "1",
            logic_value_home: get_string!(&resp_root, "LOGIC_VALUE_HOME"),
            logic_value_factory: get_string!(&resp_root, "LOGIC_VALUE_FACTORY"),
            binary_nature: get_value!(&resp_root, "BINARY_NATURE") == "1",
        })
    }

    /// Create an async byte stream for downloading the specified firmware with
    /// the specified byte range.
    pub async fn download(
        &mut self,
        info: &FirmwareInfo,
        range: Range<u64>,
    ) -> Result<impl Stream<Item = reqwest::Result<Bytes>>, FusError> {
        // It is necessary to inform the service of the intention to download
        let nonce = self.ensure_nonce().await?;
        let req_root = Self::create_binary_init_elem(info, nonce);

        let url = format!("{FUS_BASE_URL}/NF_DownloadBinaryInitForMass.do");
        self.execute_fus_xml_request(&url, &req_root, false).await?;

        // Download binary. This intentionally does not use RequestBuilder.query() because FUS has
        // been updated to return HTTP 405 if the requested filename is URL-encoded.
        let url = format!(
            "{}/NF_DownloadBinaryForMass.do?file={}{}",
            DOWNLOAD_BASE_URL,
            info.path,
            info.filename,
        );

        debug!("Requesting bytes {}-{} from: {url}", range.start, range.end);

        let r = self.execute_fus_request(
            self.client.get(&url)
                .header(RANGE, format!("bytes={}-{}", range.start, range.end)),
            true,
        ).await?;
        let status = r.status();

        if status != StatusCode::PARTIAL_CONTENT {
            return Err(FusError::BadHttpResponse(StatusCode::PARTIAL_CONTENT, status));
        }

        Ok(r.bytes_stream())
    }

    fn create_text_node(name: &str, text: &str) -> XMLNode {
        let mut elem = Element::new(name);
        elem.children.push(XMLNode::Text(text.to_owned()));
        XMLNode::Element(elem)
    }

    fn create_data_node(name: &str, value: &str) -> XMLNode {
        let mut elem = Element::new(name);
        elem.children.push(Self::create_text_node("Data", value));
        XMLNode::Element(elem)
    }

    fn create_fus_hdr_node() -> XMLNode {
        let mut elem = Element::new("FUSHdr");
        elem.children.push(Self::create_text_node("ProtoVer", "1.0"));
        elem.children.push(Self::create_text_node("SessionID", "0"));
        elem.children.push(Self::create_text_node("MsgID", "1"));
        XMLNode::Element(elem)
    }

    fn create_binary_inform_elem(
        model: &str,
        region: &str,
        version: &FwVersion,
        nonce: Nonce,
        binary_nature: bool,
    ) -> Element {
        use LogicCheckType::Data;

        let mut fus_body = Element::new("FUSBody");

        let mut put = Element::new("Put");
        put.children.push(Self::create_text_node("CmdID", "1"));
        put.children.push(Self::create_data_node("ACCESS_MODE", "2"));
        put.children.push(Self::create_data_node("BINARY_NATURE",
            if binary_nature { "1" } else { "0" }));
        put.children.push(Self::create_data_node("CLIENT_PRODUCT", "Smart Switch"));
        put.children.push(Self::create_data_node("DEVICE_MODEL_NAME", model));
        put.children.push(Self::create_data_node("DEVICE_LOCAL_CODE", region));
        put.children.push(Self::create_data_node("DEVICE_FW_VERSION", &version.to_string()));
        put.children.push(Self::create_data_node("DEVICE_VER_COUNT", "4"));
        put.children.push(Self::create_data_node("DEVICE_PDA_CODE1_VERSION", &version.pda));
        put.children.push(Self::create_data_node("DEVICE_CSC_CODE2_VERSION", &version.csc));
        put.children.push(Self::create_data_node("DEVICE_PHONE_FONT_VERSION", &version.phone));
        put.children.push(Self::create_data_node("DEVICE_CONTENTS_DATA_VERSION", &version.data));
        put.children.push(Self::create_data_node("LOGIC_CHECK",
            &nonce.to_logic_check(Data(version.to_string().as_bytes()))));
        fus_body.children.push(XMLNode::Element(put));

        let mut get = Element::new("Get");
        get.children.push(Self::create_text_node("CmdID", "2"));
        get.children.push(Self::create_text_node("LATEST_FW_VERSION", ""));
        fus_body.children.push(XMLNode::Element(get));

        let mut fus_msg = Element::new("FUSMsg");
        fus_msg.children.push(Self::create_fus_hdr_node());
        fus_msg.children.push(XMLNode::Element(fus_body));

        fus_msg
    }

    fn create_binary_init_elem(info: &FirmwareInfo, nonce: Nonce) -> Element {
        use LogicCheckType::Filename;

        let mut fus_body = Element::new("FUSBody");

        let mut put = Element::new("Put");
        put.children.push(Self::create_text_node("CmdID", "1"));
        put.children.push(Self::create_data_node("DEVICE_MODEL_TYPE",
            &info.model_type.to_string()));
        put.children.push(Self::create_data_node("BINARY_NATURE",
            if info.binary_nature { "1" } else { "0" }));
        put.children.push(Self::create_data_node("DEVICE_LOCAL_CODE", &info.region));
        put.children.push(Self::create_data_node("BINARY_VERSION",
            &info.version.to_string()));
        put.children.push(Self::create_data_node("BINARY_FILE_NAME", &info.filename));
        put.children.push(Self::create_data_node("LOGIC_CHECK",
            &nonce.to_logic_check(Filename(&info.filename))));
        fus_body.children.push(XMLNode::Element(put));

        let mut get = Element::new("Get");
        get.children.push(Self::create_text_node("CmdID", "2"));
        get.children.push(Self::create_text_node("BINARY_EMERGENCY_OTP_SEND", ""));
        fus_body.children.push(XMLNode::Element(get));

        let mut fus_msg = Element::new("FUSMsg");
        fus_msg.children.push(Self::create_fus_hdr_node());
        fus_msg.children.push(XMLNode::Element(fus_body));

        fus_msg
    }

    fn get_elem_text<'a>(elem: &'a Element, path: &[&str]) -> Option<Cow<'a, str>> {
        let mut result = Some(elem);

        for p in path {
            result = result.and_then(|e| e.get_child(*p));
        }

        result.map(|e| e.get_text().unwrap_or(Cow::Borrowed("")))
    }

    fn get_fus_field<'a>(elem: &'a Element, field: &str) -> Option<Cow<'a, str>> {
        Self::get_elem_text(elem, &["FUSBody", "Put", field, "Data"])
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_authorization() {
        assert_eq!(Authorization::new().to_string(),
                   r#"FUS nonce="", signature="", nc="", type="", realm="", newauth="1""#);

        assert_eq!(Authorization::with_signature("abc").to_string(),
                   r#"FUS nonce="", signature="abc", nc="", type="", realm="", newauth="1""#);
    }

    #[test]
    fn test_nonce() {
        let keys = FusKeys::new(
            b"testing_testing_testing_testing_",
            b"testing_testing_",
        ).unwrap();

        assert_matches!(Nonce::from_slice(b"testing_testing_"), Ok(_));
        assert_matches!(Nonce::from_slice(b"testing_testing"),
                        Err(FusError::NonceInvalidSize));
        assert_matches!(Nonce::from_slice(b"testing_testing_t"),
                        Err(FusError::NonceInvalidSize));

        assert_eq!(Nonce::from_slice(b"testing_testing_").unwrap().to_string(),
                   "testing_testing_");
        assert_eq!(Nonce::from_slice(b"\xffesting_testing_").unwrap().to_string(),
                   "[Non-UTF-8 data]");

        assert_eq!(Nonce::from_slice(b"testing_testing_").unwrap().to_encrypted(&keys),
                   "yrJiFOygpIxnq4nbWdT2NLk1Odu8m5+zcFKQL4PzV0A=");

        assert_matches!(Nonce::from_encrypted(&keys, b"yrJiFOygpIxnq4nbWdT2NLk1Odu8m5+zcFKQL4PzV0A="),
                        Ok(x) if x == Nonce::from_slice(b"testing_testing_").unwrap());
    }

    #[test]
    fn test_nonce_signature() {
        let keys = FusKeys::new(
            b"testing_testing_testing_testing_",
            b"testing_testing_",
        ).unwrap();

        assert_eq!(Nonce::from_slice(b"testing_testing_").unwrap().to_signature(&keys),
                   "9J2R5S8AAXs40SYA92cLHQfWDv/6w5cAeZkPOEDIFGw=");
    }

    #[test]
    fn test_logic_check() {
        use LogicCheckType::*;

        let nonce = Nonce::from_slice(b"testing_testing_").unwrap();

        assert_eq!(nonce.to_logic_check(Data(b"abc")), "bcabacbabcabacba");
        assert_eq!(nonce.to_logic_check(Data(b"testing_testing_")), "intieg__intieg__");

        assert_eq!(nonce.to_logic_check(Filename("abc")), "bcabacbabcabacba");
        assert_eq!(nonce.to_logic_check(Filename("testing_testing_.enc4")), "intieg__intieg__");
        assert_eq!(nonce.to_logic_check(Filename("testing_testing_testing_.enc4")), "intieg__intieg__");
    }
}
