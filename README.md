# Ansible-Vault-UI

## About The Project

Ansible-Vault-UI is a TUI (Text User Interface) for ansible-vault command-line tool written in rust.

[![Product ScreenShot 1][product-screenshot-1]]
[![Product ScreenShot 2][product-screenshot-2]]

## Usage
Application have hotkeys:
    ```
    Esc - Menu, q - Quit application
    ```

## Features list
1. Enter password only one time and work with all files till close app
2. Transparent file encryption decryption
3. Automatic backup of previous file versions
4. Works on both Windows and Linux OS

## Manual build
1. Install rust
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
2. Clone the repo
   ```sh
   git clone https://github.com/vaassi/ansible-vault-ui.git
   ```
3. Run cargo to build project
    ```sh
    cargo build
    ```

## Contributing
Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
Distributed under the MIT License. See `LICENSE.txt` for more information.

[product-screenshot-1]: https://github.com/vaassi/ansible-vault-ui/images/screenshot1.png
[product-screenshot-1]: https://github.com/vaassi/ansible-vault-ui/images/screenshot2.png