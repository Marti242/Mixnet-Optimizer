Minimal implementation of the [Loopix mix network design](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska) for simulating traffic through the network and optimizing its parameters.

# How to run

```
$ python runner.py --layers 3 --providers 2 --tracesFile <path_to_traces_file> --nodesPerLayer 2
```

### Arguments:

- `layers` - number of layers in the mixnet.
- `providers` - number of providers in the mixnet.
- `tracesFile` - a path to a JSON file with legitimate traffic traces that should be mimicked in the simulation. It should hold a list of email objects (definition of email object below).
- `nodesPerLayer` - number of nodes in a single layer of a mixnet.

#### Email Object Fields:

- `time` - timestamp, relative to the time at which the messages should start to flow.
- `sender` - the user ID of the sending entity. `u` followed by 6 digit ID string (there are over 100k users in the training set).
- `size` - the number of bytes in a plaintext mail message.
- `receiver` - the user ID of the receiving entity. The same format as the sender.

### Output

A `logs.log` file in the `logs` directory. Logging format:

```
INFO:root:<timestamp> <sender_ID> <receiver_ID> <message_ID> <chunk_number> <traffic_type>
```

- `timestamp` - time at which the message was sent.
- `sender_ID` - ID of the sending entity. The first letter defines the type of the sending entity. It is followed by 6 digit ID string.
  - `u` for user.
  - `m` for mix
  - `p` for provider.
- `receiver_ID` - same as `sender_ID` but for receiver.
- `message_ID` - the `pymongo bson ObjectId` string to identify a message. When a `LEGIT` message is split into chunks all of the chunks have the same `message_ID`. A combination of `message_ID` and `chunk_number` uniquely identifies any packet. Multiple packets of the same message having the same `message_ID` make it easier to compute E2E latency for the entire message.
- `chunk_number` - an ordinal identifier that helps to rebuild message split into chunks back to original.
- `traffic_type` - the type of the sent packet, `LEGIT`, `DROP`, `LOOP` or `LOOP_MIX`.

A sample of logging format:

```
INFO:root:1632036003.2179623 m000003 m000004 6146e477db3de34f0b4b27ff 00000 DROP
INFO:root:1632036004.1910408 p000000 u073503 6146e46bdb3de34f0b4b27eb 00000 LEGIT
INFO:root:1632036004.1971738 p000000 m000002 6146e479db3de34f0b4b2801 00000 LOOP
INFO:root:1632036003.0823636 m000002 m000002 6146e486db3de34f0b4b2813 00000 LOOP_MIX
```

**TO DO: ADD ASUMPTIOS & implementation details**
