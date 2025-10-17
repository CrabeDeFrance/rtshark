# 4.1.0 (2025-10-17)

## Features

- Add a new API to set a configuration profile (#30).

# 4.0.1 (2025-10-14)

## Fixes

- Fix compilation with no-default-features (#33).

# 4.0.0 (2025-10-12)

## Features

- Add new async API, thanks to "TheMagicNacho" (#29). It includes a major refactoring, so major number moved to 4.0.

# 3.2.0 (2025-05-25)

## Features

- Add new API enable_protocol to enable specific protocols, thanks to "Maxime Bruno".
- Add [must_use] keyword on builder functions to ensure proper usage.

# 3.1.0 (2024-12-22)

## Features

- Add new batch API thanks to "bbannier" (#25)

# 3.0.0 (2024-11-16)

## Features

- Update metadata structure. Fields display, size and position are optional.

# 2.10.0 (2024-11-16)

## Features

- New API to change behavior of protocols (tshark -o) thanks to "Jamie Hodkinson"
- New API to disable protocol (tshark --disable-protocol) thanks to "Jamie Hodkinson"
- Update dependencies to their latest version

# 2.9.0 (2024-09-15)

## Features

- New API to get rtshark versioning information (Thanks to "lrstewart").
- Update dependencies to their latest version

# 2.8.0 (2024-06-24)

## Features

- Extract relevant protocol metadata from virtual layer 'fake-field-wrapper' (Thanks to "lrstewart" #16)
  This is needed to extract tcp.reassembled.data.
- Add raw_value metadata API to get access to "value" XML attribute (Thanks to "lrstewart" #17)
  This feature may decrease performance because "raw" values are bigger than usual.
- Add support for multiple interfaces (#15)

## Fixes

- Update dependencies to their latest version

# 2.7.1 (2023-11-06)

## Fixes

- Fix missing sub-metadata - child fields (Thanks to "DennisNemec").

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
