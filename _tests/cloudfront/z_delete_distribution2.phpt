--TEST--
CloudFront: delete_distribution() with streaming.

--FILE--
<?php
	// Dependencies
	require_once dirname(__FILE__) . '/../../cloudfusion.class.php';

	// Retrieve the cached Distribution ID. See create_distribution() for why we're doing this.
	$distribution_id = file_get_contents('create_distribution_stream.cache');

	$cdn = new AmazonCloudFront();

	// Fetch an updated ETag value
	$etag = $cdn->get_distribution_config($distribution_id)->header['etag'];

	// Set the updated config XML to the distribution.
	$response = $cdn->delete_distribution($distribution_id, $etag);

	// Success?
	var_dump($response->isOK());

	// If the delete request was successful, delete the cached file.
	if ($response->isOK())
	{
		unlink('create_distribution_stream.cache');
	}
?>

--EXPECT--
bool(true)
