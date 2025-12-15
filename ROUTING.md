ROUTING MD

The routing of a miv is simple in theory:
Assume we have three parties:
Alice
Joe
Bob

Alice sends a message to Bob but it goes via Joe. Joe has the option to approve (forward) the routing to Bob or reject the message back to Alice. Via routing is used when sending requests for approval (asking superiors for approval on action) or when sending orders down to junior personnel. The person that is the via terminal would be the middle manager for example.

When Alice sends the message, she will see it in her SENT. She has her own copy of this miv in the database. Another copy is created and sent to Joe of this miv. When joe reads it, it does NOT send a read receipt to Alice as Bob still hasn't read the message (we only care about Bob reading it as the message is for him).

When Joe fowards the message to Bob, another copy is created and sent to Bob. The miv no longer appears in Joe's baskets but simply remains visible in the CONVERSATIONS view. This logic is based on the fact that he has no outstanding mivs that he needs to do anything with.

Once Bob gets the Miv, he answers/acks it. Joe sees the miv and forwards to Alice. And so it goes, back and forth until an ACK is sent and then the other party deletes the ack.
