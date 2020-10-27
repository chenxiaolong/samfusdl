# samfusdl

samfusdl is an unofficial tool for downloading firmware images from Samsung's FUS (firmware update service).

Features:
* Downloads firmware chunks in parallel for faster downloads
* Interrupted downloads can be resumed
* Supports downloading both home and factory images
* Supports both old and new-style firmware decryption (`.enc2` and `.enc4`)
* Supports downloading the latest firmware or a specific version
* Supports AES-NI for fast firmware decryption on x86_64 (falls back to SIMD for other CPU architectures or if AES-NI is not available)

## Encryption keys

Access to FUS requires two encryption keys: the fixed key and the flexible key suffix. These are the same for every user and are hard-coded into the official clients. **samfusdl does not and will never include these encryption keys.** You must acquire them yourself.

**Please do not open any issues or contact the author about how to reverse-engineer any of the official clients. They will be ignored.**

Once you have the keys, there are a few different ways to make them available to samfusdl:

* Inside the config file:

  * Windows: `%APPDATA%\samfusdl.conf` (eg. `C:\Users\<user>\AppData\Roaming\samfusdl.conf`)
  * Linux (and other unix-like OS's): `$XDG_CONFIG_HOME/samfusdl.conf` or `~/.config/samfusdl.conf`
  * macOS: `~/Library/Application Support/samfusdl.conf`

  Contents:

  ```json
  {
      "fus_fixed_key": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      "fus_flexible_key_suffix": "XXXXXXXXXXXXXXXX"
  }
  ```

* As environment variables:

  sh/bash/zsh:

  ```sh
  export FUS_FIXED_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  export FUS_FLEXIBLE_KEY_SUFFIX=XXXXXXXXXXXXXXXX
  ```

  powershell:

  ```powershell
  $env:FUS_FIXED_KEY = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
  $env:FUS_FLEXIBLE_KEY_SUFFIX = 'XXXXXXXXXXXXXXXX'
  ```

* As command-line arguments:

  When running `samfusdl`, add the `--fus-fixed-key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` and `--fus-flexible-key-suffix XXXXXXXXXXXXXXXX` arguments.

## Usage

To download the latest firmware for a device, run:

```
samfusdl -m <model> -r <region>
```

For example:

```
samfusdl -m SM-N986U -r TMB
```

To download a specific firmware version, use the `-v`/`--version` argument. For example:

```
samfusdl -m SM-N986U -r TMB -v N986USQU1ATGM/N986UOYN1ATGM
```

To change the output path, use the `-o <filename>` argument.

By default, firmware files are downloaded with 4 parallel connections. This can be changed using the `-c`/`--chunks` argument.

To interrupt a download, simply use Ctrl-C as usual. Rerunning the same command will resume the download.

For more information about other command-line arguments, see `--help`.

## Building from source

To build from source, first make sure that the Rust toolchain is installed. It can be installed from https://rustup.rs/ or the OS's package manager.

Build samfusdl using the following command:

```
cargo build --release
```

The resulting executable will be in `target/release/samfusdl` or `target\release\samfusdl.exe`.

## Debugging

Debug logging can be enabled with the `--loglevel debug` argument. This will disable the fancy progress bar and print out significantly more information, such as how the parallel download chunks are split. Note that encryption keys are not logged unless the `SAMFUSDL_LOG_KEYS` environment variable is set to `true`.

If `--loglevel trace` is set, each file I/O operation during the download stage is logged. This is generally not useful for anything besides debugging the parallel download mechanism or `pwrite`/overlapped-I/O.

Instead of setting `--loglevel`, it is also possible to set the `RUST_LOG` environment variable, which allows log messages of samfusdl's dependencies to be printed out.

To debug the actual HTTP requests and responses, any HTTPS-compatible MITM software, like mitmproxy, can be used. samfusdl respects both the OS proxy settings and the `http_proxy`/`https_proxy` environment variables. Note that TLS certificate validation is enabled by default. The MITM software's CA certificate will either need to be added to the OS's trust store or the `--ignore-tls-validation` argument can be used.

## Caveats

* For Windows, only Windows 10 1607 and newer are supported. samfusdl uses atomic file rename/replace, which isn't supported on earlier versions of Windows.

## License

samfusdl is licensed under the GPLv3 license. For details, please see [`LICENSE`](./LICENSE).

## TODO

* Add command line argument for picking home vs. factory firmware.
* Stop using FOTA for querying the latest firmware as it does not work for `ATT` or `VZW`.
