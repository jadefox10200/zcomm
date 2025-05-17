
# zPC Protocol Buffers Schema

## Overview
The `zPC.proto` file defines a set of Protocol Buffers (Protobuf) messages for a messaging or dispatch system. It enables efficient, cross-platform serialization of structured data for communication between services. This schema is designed for use in a Go application, where messages can be serialized/deserialized using generated Go code.

## Messages
The schema defines five messages, each representing a specific type of data structure:

1. **SendDispatch**
   - Represents a dispatch message sent from one entity to another.
   - Fields:
     - `from_zid` (string): Sender's identifier.
     - `to_zid` (string): Recipient's identifier.
     - `dispatch_uuid` (string): Unique identifier for the dispatch.
     - `conversation_id` (string): Identifier for the conversation.
     - `seq_no` (uint32): Sequence number for ordering.
     - `ephemeral_pub_key` (string): Ephemeral public key for encryption.
     - `signature` (bytes): Cryptographic signature of the message.
     - `body` (bytes): Message content.
     - `nonce` (string): Nonce for security.

2. **ReceiveDispatch**
   - Represents a confirmation of a received dispatch.
   - Fields:
     - `client_zid` (string): Client's identifier.
     - `last_seen_uuid` (string): UUID of the last dispatch seen.

3. **NewDispatch**
   - Represents metadata for a new dispatch.
   - Fields:
     - `dispatch_uuid` (string): Unique dispatch identifier.
     - `from_zid` (string): Sender's identifier.
     - `conversation_id` (string): Conversation identifier.
     - `timestamp` (uint64): Dispatch creation time (e.g., Unix timestamp).

4. **FetchPublicKeys**
   - Requests public keys for multiple entities.
   - Fields:
     - `target_zids` (repeated string): List of entity identifiers to fetch keys for.

5. **VerifySignature**
   - Requests verification of a dispatch's signature.
   - Fields:
     - `dispatch_uuid` (string): Dispatch identifier.
     - `from_zid` (string): Sender's identifier.
     - `signature` (bytes): Signature to verify.

## Using in Go

### Prerequisites
- Install the Protocol Buffers compiler (`protoc`): [Protocol Buffers Installation](https://grpc.io/docs/protoc-installation/).
- Install the Go Protobuf plugin:
  ```bash
  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
  ```

### Compiling the Schema
Generate Go code from `zPC.proto`:
```bash
protoc --go_out=. zPC.proto
```
This creates a `zpc.pb.go` file in the same directory, containing Go structs and methods for the messages.

### Example Go Code
Below is a simple example of using the generated code to create and serialize a `SendDispatch` message:

```go
package main

import (
	"fmt"
	"log"

	"google.golang.org/protobuf/proto"
	"path/to/your/module/zpc" // Replace with your module path
)

func main() {
	// Create a SendDispatch message
	dispatch := &zpc.SendDispatch{
		FromZid:        "sender123",
		ToZid:          "receiver456",
		DispatchUuid:   "dispatch789",
		ConversationId: "conv001",
		SeqNo:          1,
		EphemeralPubKey: "ephemeral_key",
		Signature:      []byte{0x01, 0x02, 0x03},
		Body:           []byte("Hello, world!"),
		Nonce:          "nonce123",
	}

	// Serialize to bytes
	data, err := proto.Marshal(dispatch)
	if err != nil {
		log.Fatalf("Failed to serialize: %v", err)
	}

	// Deserialize back to a message
	newDispatch := &zpc.SendDispatch{}
	if err := proto.Unmarshal(data, newDispatch); err != nil {
		log.Fatalf("Failed to deserialize: %v", err)
	}

	// Print the deserialized message
	fmt.Printf("Deserialized: %+v\n", newDispatch)
}
```

### Module Setup
Ensure your Go module includes the Protobuf runtime dependency:
```bash
go get google.golang.org/protobuf
```

Place `zPC.proto` and the generated `zpc.pb.go` in your module (e.g., `yourmodule/zpc`). Update the import path in your code to match your module structure.

## Notes
- **Efficiency**: Protobuf is compact and fast, ideal for network communication (e.g., gRPC or custom protocols).
- **Schema Evolution**: Add new fields without breaking compatibility, but avoid changing field numbers or types.
- **gRPC**: If using gRPC, define a `service` in `zPC.proto` and generate gRPC code with `--go-grpc_out`.
- **Validation**: Protobuf doesn't enforce field presence. Add application-level checks for required fields.

## Next Steps
- Extend the schema with additional messages or services as needed.
- Integrate with a gRPC server/client for RPC communication.
- Add validation logic for fields like `dispatch_uuid` or `signature`.

For questions or help with implementation, refer to the [Protocol Buffers Go Documentation](https://developers.google.com/protocol-buffers/docs/gotutorial) or contact the project maintainer.

