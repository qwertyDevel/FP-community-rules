rule CVE_2015_3397
{
	meta:
			component_name = "YiiFramework"
            component_version = "2.0.3"
            custom_title = "CVE-2015-3397 XSS vulnerability in YiiFramework before 2.0.4"
            custom_level = "Medium"
            custom_description = "<p>Cross-site scripting (XSS) vulnerability in Yii Framework before 2.0.4 allows remote attackers to inject arbitrary web script or HTML via vectors related to JSON, arrays, and Internet Explorer 6 or 7. </p>"

	strings:
			$ver = /2.0.3/

	condition:
			php_file and YiiFramework and $ver
}

private rule YiiFramework
{
	meta:
			custom_description = "Private rule for indentifying YiiFramework"

	strings:
			$baseyii = /^class BaseYii/ nocase

	condition:
			$baseyii
}