# Java vs Web Comparison

Fixture: `/Users/ahmadjalil/Downloads/REON+POCKET_2.2.0_APKPure.xapk`

| Output | Bytes | Entries | Signing block | v2 verifies | Resource summary | Warnings |
| --- | ---: | ---: | --- | --- | --- | --- |
| Java/REAndroid unsigned | 22629984 | 1025 | APK Signature Scheme v2, APK Signature Scheme v3, APK Source Stamp, Unknown 2146444e, Unknown 42726577 | no | 454.3 KB resources.arsc, 1 package(s) (jp.co.sony.reonpocket), 68 type config chunk(s), 4804 populated entries | APK still contains 2 pre-existing JAR signature file(s).<br>v2 content digest did not match recomputed APK digest. |
| Web unsigned | 23220462 | 1022 | none | no | 451.7 KB resources.arsc, 1 package(s) (jp.co.sony.reonpocket), 72 type config chunk(s), 4805 populated entries | APK Signing Block not found. |
| Web v1+v2 | 23310320 | 1025 | APK Signature Scheme v2 | yes | 451.7 KB resources.arsc, 1 package(s) (jp.co.sony.reonpocket), 72 type config chunk(s), 4805 populated entries |  |

## Entry Differences

Only Java: 3

- `META-INF/BNDLTOOL.RSA`
- `META-INF/BNDLTOOL.SF`
- `META-INF/MANIFEST.MF`

Only web: 0


Different uncompressed sizes:

- `AndroidManifest.xml`: Java 26920, web 27328
- `resources.arsc`: Java 465160, web 462500

## Findings

- Java output contains a carried APK Signing Block, but its v2 digest does not verify after merging.
- Web unsigned output strips stale signing material and has no v2 block.
- Web v2 output contains a browser-generated v2 block that verifies with the local verifier.
