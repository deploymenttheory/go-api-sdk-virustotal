# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2](https://github.com/deploymenttheory/go-api-sdk-virustotal/compare/v0.1.1...v0.1.2) (2026-02-13)


### Bug Fixes

* added client options 'WithRetryWaitTime' and 'WithRetryMaxWaitTime' ([4b4dd58](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/4b4dd58c4e05ae843c5db6ab58722b506e1ffb38))
* added client options 'WithRetryWaitTime' and 'WithRetryMaxWaitTime' ([b533fa3](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/b533fa3ef19bb42d728eafe42b0555d278bee419))

## [0.1.1](https://github.com/deploymenttheory/go-api-sdk-virustotal/compare/v0.1.0...v0.1.1) (2026-02-13)


### Bug Fixes

* added graceful handling for uploads, handling small and large files with appropriate endpoints; update file upload logic to support size-based endpoint selection ([def6825](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/def6825074557d00ec8bb9ea2ff7c45ee08bddb7))
* added graceful handling for uploads, handling small and large files with appropriate endpoints; update file upload logic to support size-based endpoint selection ([9273e3d](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/9273e3d036a34a625f4fac7b8fd86c298ebb457b))

## 0.1.0 (2026-02-13)


### Features

* add comments service to VirusTotal API client ([bf0bcc0](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/bf0bcc0524351e4fa89d5510fe1be60ebb5d6c8b))
* add customizable HTTP client options including user agent, global headers, proxy settings, and TLS configurations ([86aac0e](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/86aac0ec66fdc51655e97460473bd45374672af8))
* add file_behaviours and urls services, enhance HTTP client with PostForm and GetBytes methods ([1c2cacd](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/1c2cacd563ef5faada27388776cc15a3a32ac521))
* add popular_threat_categories service to VirusTotal API client ([863f471](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/863f471ca9fd725029c5fec9561219fd4718e6d3))
* added code insights to api sdk ([eed9092](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/eed9092eaa1ad1aa2a3dceb4206b48afc37c5249))
* added ip_addresses, files and domains as sdk services with examples ([1944f3d](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/1944f3da88a9170f04eed84af681a39385de33ae))
* added support for open telemetry and doc updates ([2f5da2c](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/2f5da2c3fad3b88c6e519ce5cbc94b8555620de9))
* added support for open telemetry and doc updates ([9728451](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/972845102e1de2242a423bbc5b6a1c539619960f))
* added yara rules ([e88f6f3](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/e88f6f321eb50c0ee949081d1271c054573c250b))
* enhance response handling in API client by adding duration, received time, and size fields to the response structure ([d2eb96a](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/d2eb96a423144aabdab6e6aa2466715925fe5490))
* enhance response handling in API client by adding duration, received time, and size fields to the response structure ([6b53fd3](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/6b53fd34b3c3329abe8f8a883e772f24c5304e19))
* enhance VirusTotal API client with relationship endpoints for analyses, attack tactics, comments, file behaviours, and urls ([8c292ed](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/8c292ed3a95d11a7c941388f8c981ef2fe47b165))
* implement domain and file relationship endpoints in VirusTotal API client ([e2c4258](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/e2c42585d43358682fc4074c3bb66e2107191e04))
* integrate analyses and attack_tactics services into VirusTotal API client ([110eb9a](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/110eb9a050e86f08a0443d5c34cfd075b1d5f363))


### Bug Fixes

* implement NewEmptyResponse function for consistent error handling across API calls in analyses, attack tactics, comments, and more ([3b47adf](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/3b47adf725a770a36df054f4f704a6420890190f))
* update acceptance tests to ensure response handling is consistent for validation errors across analyses, domains, files, IP addresses, and URLs ([e1fd4b2](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/e1fd4b286c042904b50c801b381ec1d08f86a85f))
* update acceptance tests to ensure response is not nil for API errors across analyses, domains, files, and IP addresses ([9a7da45](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/9a7da45d4590443fe9872af19eb90a168a20e4c2))
* update acceptance tests to improve error messages and validation checks ([0b07ac5](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/0b07ac516a7a6810d2a348080702e88735a78c70))
* update API calls to handle response objects correctly by including response in error handling for analyses, domains, files, IP addresses, and URLs ([6f9ae70](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/6f9ae70e911c099112e88fab48e478722900c830))
* update API calls to handle response objects correctly by including response in error handling for analyses, domains, files, IP addresses, and URLs ([d26e917](https://github.com/deploymenttheory/go-api-sdk-virustotal/commit/d26e9179033686eafc53eea4579af752546a1476))

## [Unreleased]

### Added

- Added xyz [@your_username](https://github.com/your_username)

### Fixed

- Fixed zyx [@your_username](https://github.com/your_username)

## [1.1.0] - 2021-06-23

### Added

- Added x [@your_username](https://github.com/your_username)

### Changed

- Changed y [@your_username](https://github.com/your_username)

## [1.0.0] - 2021-06-20

### Added

- Inititated y [@your_username](https://github.com/your_username)
- Inititated z [@your_username](https://github.com/your_username)
