# Java vs Web Comparison

Fixture: `/Users/ahmadjalil/Downloads/librelinkup/LibreLinkUp_5.0.1_APKPure.xapk`

| Output | Bytes | Entries | Signing block | v2 verifies | Resource summary | Warnings |
| --- | ---: | ---: | --- | --- | --- | --- |
| Java/REAndroid unsigned | 67637064 | 1029 | APK Signature Scheme v2, APK Signature Scheme v3, APK Source Stamp, Unknown 2146444e, Unknown 42726577 | no | 663.7 KB resources.arsc, 1 package(s) (org.nativescript.LibreLinkUp), 71 type config chunk(s), 6865 populated entries | APK still contains 2 pre-existing JAR signature file(s).<br>v2 content digest did not match recomputed APK digest. |
| Web unsigned | 62264578 | 1026 | none | no | 660.3 KB resources.arsc, 1 package(s) (org.nativescript.LibreLinkUp), 76 type config chunk(s), 6866 populated entries | APK Signing Block not found. |
| Web v1+v2 | 62356714 | 1029 | APK Signature Scheme v2 | yes | 660.3 KB resources.arsc, 1 package(s) (org.nativescript.LibreLinkUp), 76 type config chunk(s), 6866 populated entries |  |

## Entry Differences

Only Java: 3

- `META-INF/BNDLTOOL.RSA`
- `META-INF/BNDLTOOL.SF`
- `META-INF/MANIFEST.MF`

Only web: 0


Different uncompressed sizes:

- `AndroidManifest.xml`: Java 18812, web 19192
- `resources.arsc`: Java 679660, web 676184

## Findings

- Java output contains a carried APK Signing Block, but its v2 digest does not verify after merging.
- Web unsigned output strips stale signing material and has no v2 block.
- Web v2 output contains a browser-generated v2 block that verifies with the local verifier.
