# Pre-built binaries

## Download

Download the latest release from the [GNOBAN releases page](https://github.com/caesrcd/gnoban/releases).

## Verify your download

1. Download the list of cryptographic checksums: **SHA256SUMS**

2. Download the signature file: **SHA256SUMS.asc**

3. Open a terminal (command prompt) and change the directory (`cd`) to your downloads folder.

4. Verify that the checksum of the downloaded file is listed in the checksum file using one of the following commands:

  - ***Linux***
    ```bash
    sha256sum --ignore-missing --check SHA256SUMS
    gnoban-1.3.0-x86_64-linux-gnu.tar.gz: OK
    ```

  - ***MacOS***
    ```bash
    shasum -a 256 --ignore-missing --check SHA256SUMS
    gnoban-1.3.0-x86_64-apple-darwin.zip: OK
    ```

  - ***Windows***
    ```bash
    certUtil -hashfile gnoban-1.3.0-win64.zip SHA256
    ```

    Ensure that the checksum produced by the command above matches one of the entries in the SHA256SUMS file. You can display the file contents with:

    ```bash
    type SHA256SUMS
    ```

5. If you haven’t already installed GNU Privacy Guard (GPG), [download it here](<https://gpg4win.org/download.html>) or see other [installation options](<https://www.gnupg.org/download/index.en.html#binary>).

6. To verify the signature, import the project’s public key and check that the checksum file was signed by a trusted key:

    ```bash
    gpg --keyserver hkps://keys.openpgp.org --recv-keys E2A0BF0D72D74483064D4FF9304952407A6E5C38
    gpg --verify SHA256SUMS.asc
    ```

## Install the binary

### Linux

```bash
tar xzf gnoban-1.3.0-linux-gnu.tar.gz
sudo install gnoban-1.3.0/gnoban /usr/local/bin/
```

### MacOS

```bash
unzip gnoban-1.3.0-apple-darwin.zip
sudo install gnoban-1.3.0/gnoban /usr/local/bin/
```

### Windows

Extract the `.zip` file and move the files to `%USERPROFILE%\AppData\Local\GNOBAN`.

Then add the installation directory to your `PATH` environment variable:

1. Open **Start** and search for *Edit the system environment variables*.
2. Click **Environment Variables**.
3. Under *User variables*, select **Path** and click **Edit**.
4. Click **New** and add `%USERPROFILE%\AppData\Local\GNOBAN`.
5. Click **OK** to apply.

To test, run `gnoban --version`.
