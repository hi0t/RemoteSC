# RemoteSC

RemoteSc provides access to the smart card for client applications that do not have local access to them. The server runs on a local computer with a smart card installed. The client application loads the librpkcs11 module and forward high-level interface PKCS#11 to the server. The TLS protocol is used for secure communication between components.

## An example of using YubiKey from Windows Subsystem for Linux (WSL)
*   Install server in Windows

    ```
    remotesc.exe install --provider "C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll" --listen "<vEthernet (WSL)>"
    ```

    The command will install RemoteSC as a service and out a configuration with a shared secret:

    ```
    {
        "fingerprint": "6dF48TTAZtJwGd3jzPOo+rWjcuyfVw/Mb/YV3JLuCF4=",
        "secret": "JEQO8S9fg6uNkPV7/ie121LzaqQsIRiKerby85Y89SM="
    }
    ```

*   Then configure the client `librpkcs11.so` module. Put in the file `~/.config/remotesc.json` configuration given by the server.

*   Now you can use YubiKey from any application that supports the PKCS#11 interface by specifying the path to the `librpkcs11.so` module:

    ```
    ssh -I /path/to/librpkcs11.so
    ssh-keygen -I /path/to/librpkcs11.so
    ...
    ```
