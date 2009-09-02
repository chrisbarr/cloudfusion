--TEST--
AmazonSQSQueue::receive_message

--FILE--
<?php
	// Dependencies
	require_once dirname(__FILE__) . '/../../cloudfusion.class.php';

	// Receive a message
	$sqs = new AmazonSQSQueue('warpshare-unit-test');
	$response = $sqs->receive_message();

	// Store the message receipt in a temp file so that the delete message can grab it later.
	// This is The Wrong Way To Do It™
	file_put_contents('receipt_handle_queue.cache', (string) $response->body->ReceiveMessageResult->Message->ReceiptHandle); // Pass data to delete_message.

	// Success?
	var_dump($response->isOK());
?>

--EXPECT--
bool(true)
