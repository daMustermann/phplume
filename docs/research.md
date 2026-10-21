# PHP security research

Reviewed **22 October 2026**. This is a dated research snapshot, not a live vulnerability feed. The bundled phplume catalog covers the following two advisories only.

## Verified advisories

| Advisory | Issue | Severity | Detection in phplume |
| --- | --- | --- | --- |
| [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | Out-of-memory handling can leave request data partially initialized; cleanup can consume invalid memory. | Critical, CVSS 4.0 9.2 | Compare observed PHP versions to the fixed release on their own branch. |
| [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Request-owned global state can outlive the memory it refers to and be consumed by a later request. | Critical, CVSS 4.0 9.2 | The same branch-specific fix floors apply. |

Both advisories were published on 21 October 2026. They describe potential unauthenticated remote code execution. Exposure depends on SAPI, application behavior and configuration. Demonstrated mod_php exploitation makes those installations a priority. PHP-FPM and other web runtimes also require updates; their exploit conditions differ. See the advisories for the exact scope and validation status.

## Fixed upstream releases

| Branch | First fixed stable release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Sources: the two advisories above and the [PHP release announcement](https://www.php.net/archive/2026.php#2026-10-21-5). The announcement is dated 21 October; some changelog entries use 22 October. The detection rules use the explicit fixed release numbers.

## What evidence supports a finding?

- `X-Powered-By` and `Server` headers can advertise a PHP version. They can also be stale, spoofed or supplied by a proxy. phplume retains these PHP indicators and compares all advertised versions.
- A `PHPSESSID` cookie name, `.php` link or familiar PHP application marker is only a weak indicator. None establishes an exact runtime version or exploitability. Cookie values are discarded.
- `php -n -v` establishes the version of the executable that was invoked. It does not establish the version of FPM workers, Apache modules, container images or another PHP executable.
- A missing PHP header, closed port, certificate failure, error page or redirect cannot establish that the system is unaffected.

Distribution and LTS packages may backport complete patches without changing the upstream version number. An old-looking banner therefore means **potentially affected**, pending vendor verification. phplume does not guess vendor package revisions from HTTP banners and does not claim a backport is present.

## Operational response

Verify each web-serving runtime against its upstream or vendor advisory, apply a package containing both complete fixes, restart all PHP/web workers, and rebuild/redeploy containers. Confirm the deployed build after restarting. Include bundled PHP in NAS products, control panels and other appliances.

The [PHP maintainers' guidance](https://www.php.net/archive/2026.php#2026-10-21-5) states that updates provide the complete fix; configuration changes cover only some paths. phplume does not change memory limits, session settings or application configuration. Follow the official advisory for any temporary measures and their availability implications.

PHP 8.1 and earlier are outside current upstream security support. Some vendors supply backports; verify both CVEs with that vendor or move to a supported fixed branch. Consult [PHP's support policy](https://www.php.net/supported-versions.php) as support windows change.

## Deliberately excluded detection methods

The scanner sends ordinary GET requests to explicitly selected paths, at most 64 KiB of response body is examined, redirects are not followed, and response bodies are not saved. Optional speed mode first checks the selected TCP ports with asynchronous connect attempts and skips HTTP on ports that were not observed open. Those skips remain incomplete coverage; short discovery timeouts can miss real services. It sends no multipart uploads, oversized request bodies, OOM triggers, memory-corruption probes, authentication guesses, shell commands or remote PHP code. It does not request phpinfo files or crawl the site.

This makes the tool useful for triage and asset discovery. It cannot certify exploitability, absence of PHP, absence of compromise or completeness of an enterprise inventory. Consult service/package inventory and vendor advisories for systems the network view cannot identify.
