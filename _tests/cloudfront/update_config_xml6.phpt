--TEST--
CloudFront: update_config_xml() testing enabled, comments, single CNAME using a string, adding logging.

--FILE--
<?php
	// Dependencies
	require_once dirname(__FILE__) . '/../../cloudfusion.class.php';

	$cdn = new AmazonCloudFront();

	// Get the XML as a string.
	$config_xml = <<<EOF
<?xml version="1.0"?>
<Distribution xmlns="http://cloudfront.amazonaws.com/doc/2009-04-02/">
	<Id>E2L6A3OZHQT5W4</Id>
	<Status>Deployed</Status>
	<LastModifiedTime>2009-10-12T01:13:37.996Z</LastModifiedTime>
	<DomainName>d1uw7d1279vsku.cloudfront.net</DomainName>
	<DistributionConfig>
		<Origin>warpshare.test.s3.amazonaws.com</Origin>
		<CallerReference>TarzanDemo</CallerReference>
		<CNAME>cf.warpshare.com</CNAME>
		<Comment>This is my sample comment</Comment>
		<Enabled>true</Enabled>
	</DistributionConfig>
</Distribution>
EOF;

	// Update the XML content
	$response = $cdn->update_config_xml($config_xml, array(
		'Logging' => array(
			'Bucket' => 'warpshare.logging.s3.amazonaws.com',
			'Prefix' => 'wslog_'
		)
	));

	// Success?
	var_dump($response);
?>

--EXPECTF--
string(%d) "%s"
