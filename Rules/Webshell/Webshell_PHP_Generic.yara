rule webshell_php_generic_eval
{
	meta:
		description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
		hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
		date = "2021/01/07"

	strings:
        // new: eval($GLOBALS['_POST'
		$geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(\(base64_decode)?(\(stripslashes)?[\t ]*(\(trim)?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii
	
		//strings from private rule php_false_positive
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
		$gfp1  = "eval(\"return [$serialised_parameter" // elgg
		$gfp2  = "$this->assert(strpos($styles, $"
		$gfp3  = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4  = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5  = "$_POST[partition_by]($_POST["
		$gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
		$gfp8  = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
	
	condition:
		filesize < 300KB and not ( 
			any of ( $gfp* ) 
		)
		and $geval
}