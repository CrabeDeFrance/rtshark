# 2.7.0 (2023-10-08)

## Features

- New API metadata_whitelist (Thanks to "eli").
This improves a lot TShark speed.

# 2.6.0 (2023-08-15)

## Features

- Allow specifying the key log file that enables decryption of TLS traffic (Thanks to "vvv")

# 2.5.0 (2023-07-24)

## Features 

- Add new API timestamp_micros (Thanks to "vvv")
Similar to Packet.sniff_time in pyshark.

## Fixes

- Update dependencies to their latest version
And fix patch level for chrono due to a security issue before 0.4.20.

# 2.4.0 (2023-03-06)

## Features 

- Add decode-as option (Thanks to "horaih")

## Fixes

- Update dependencies to their latest version

# 2.3.1 (2022-08-14)

## Fixes 

- Update Cargo dependencies

# 2.3.0 (2022-08-14)

## Features 

- Add Windows support (Thanks to Preet Dua "Prabhpreet")

# 2.2.0 (2022-06-06)

## Fixes

- Support for TShark output without show (using pyshark style). Closes issue #1
- Filter out metadata with empty name.

# 2.1.1 (2022-05-26)

## Fixes

- Update dependencies to their latest version

# 2.1.0 (2022-05-21)

## Features

- Get TShark stderr output and return it in an Err (after filtering)

# 2.0.0 (2022-05-21)

## Features

- Rework read function API to make it more simple to use

# 1.0.0 (2022-05-18)

- First release
