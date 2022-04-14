
rule signature_name {
    meta:
        description = ""
        md5 = ""
        sha1 = ""
        filename = ""
        author = ""
    strings:
        $x= "" 
        $re1= /[0-9a-zA-Z]{32}/
        $re2= /*/ 
        $s1= "" nocase // This is a comment
        $s2= "" wide ASCII /* This is a comment */

    condition:
        (1 of $x*) or ($re1 and $re2) or (all of $s*)
}

Regular expressions -> enclosed in backslashes instead of double-quotes
Hex strings -> enclosed by curly brackets, and they are composed by a sequence of hexadecimal numbers that can appear contiguously or separated by spaces
Text strings -> enclosed on double quotes
	Can be modified - append modifier to end of string, separated by a space
		nocase -> case insensitive 
		wide -> strings encoded by 2 bytes per character
		ASCII -> ASCII characters
		xor -> searches all XOR variations for each byte
		base64 -> search for base64 encoded strings



https://yara.readthedocs.io/en/stable/writingrules.html
