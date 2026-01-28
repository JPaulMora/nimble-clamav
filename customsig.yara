rule phpmailer : webshell {
        meta:
                description = "PHP Mailer injected for mail spam"
                date = "08-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "i could not have a more welcome visitor 64 group of zain bani" fullword ascii
                $s2 = "$leaf['website']=\"leafmailer.pw\";" fullword ascii
                $s3 = "$leaf['version']" fullword ascii
        condition:
                $s1 or $s2 or $s3
}

rule ORVXpwShop: webshell {
        meta:
                description = "ORVX.pw Shell <3"
                date = "14-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "Visit our shop orvx.pw" fullword ascii
		$s2 = "shellpassword" fullword ascii
        condition:
                $s1 or $s2
}

rule TrojanBase64Generic : webshell {
        meta:
                description = "Base64 encoded payload"
                date = "08-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "ZXJyb3JfcmVwb3J0aW5nKDApOyBmdW5jdGlvbiBUb3R" fullword ascii
                $s2 = "\"b\".\"a\".\"s\".\"e\".\"6\".\"4\".\"_\".\"d\".\"e\".\"c\".\"o\".\"de\"" fullword ascii
		$s3 = "eval(base64_decode(" fullword ascii
        condition:
                $s1 or $s2 or $s3
}

rule TrojanUrldecode : webshell {
        meta:
                description = "URL encoded payload"
                date = "08-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "eval(rawurldecode(" fullword ascii
        condition:
                $s1
}

rule TrojanPHPGeneric : webshell {
        meta:
                description = "Generic PHP malware"
                date = "14-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "ZXJyb3JfcmVwb3J0aW5nKDApOyBmdW5jdGlvbiBUb3" fullword ascii
                $s2 = "\"b\".\"a\".\"s\".\"e\".\"6\".\"4\".\"_\".\"d\".\"e\".\"c\".\"o\".\"de\"" fullword ascii
		$s3 = "eval(base64_decode(" fullword ascii
		$s4 = "if(md5($_COOKIE[" fullword ascii
		$s5 = { 66 75 6e 63 74 69 6f 6e 20 ?? 31 28 24 ?? 32 29 7b 24 ?? 33 20 3d 20 22 }
        condition:
                $s1 or $s2 or $s3 or $s4 or $s5
}

rule TrojanPHPRobotsBot : bot {
        meta:
                description = "Generic PHP malware"
                date = "14-02-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
                $s1 = "fgxy0302" fullword ascii
                $s2 = "crawler" fullword ascii
                $s3 = "curl_get_contents" fullword ascii
                $s4 = "www.google.com/ping" fullword ascii
        condition:
                2 of ($s1,$s2,$s3,$s4)
}

rule WebshellAsIco : webshell {
        meta:
                description = "Generic PHP malware injected by importing an ICO file"
                date = "24-10-2022"
                threat_level = "3"
                in_the_wild = true
        strings:
		$s1 = { 40 69 6e 63 6c 75 64 65 20 22 5c 30 35 37 }
        condition:
                $s1
}