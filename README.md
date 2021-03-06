## ❗❗❗ For the new project version, check the `optimizer-0.0.3` branch. ❗❗❗

---

Minimal implementation of the [Loopix mix network design](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska) for simulating traffic through the network and optimizing its parameters.

---

# 📧 How to run

```
$ python runner.py --layers 2 --bodySize 1024 --providers 2 --tracesFile <pathToTracesFile> --nodesPerLayer 2
```

### Arguments:

- `layers` - number of layers in the mixnet.
- `bodySize` - the size of plaintext in a Sphinx packet in bytes. _(Smaller messages are padded to have this length, longer messages are split. The overall body of the Sphinx packet is a bit larger, but the sizes of all packets in the mixnet are consistent together with their headers.)_
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
INFO:root:<timestamp> <senderId> <receiverId> <messageId> <chunkNumber> <trafficType>
```

- `timestamp` - time at which the message was sent.
- `senderId` - ID of the sending entity. The first letter defines the type of the sending entity. It is followed by 6 digit ID string.
  - `u` for user.
  - `m` for mix
  - `p` for provider.
- `receiverId` - same as `senderId` but for receiver.
- `messageId` - the `pymongo bson ObjectId` string to identify a message. When a `LEGIT` message is split into chunks all of the chunks have the same `messageId`. A combination of `messageId` and `chunkNumber` uniquely identifies any packet. Multiple packets of the same message having the same `messageId` make it easier to compute E2E latency for the entire message.
- `chunkNumber` - an ordinal identifier that helps to rebuild message split into chunks back to original.
- `trafficType` - the type of the sent packet, `LEGIT`, `DROP`, `LOOP` or `LOOP_MIX`.

---

A sample of logging format:

```
INFO:root:1632036003.2179623 m000003 m000004 6146e477db3de34f0b4b27ff 00000 DROP
INFO:root:1632036004.1910408 p000000 u073503 6146e46bdb3de34f0b4b27eb 00000 LEGIT
INFO:root:1632036004.1971738 p000000 m000002 6146e479db3de34f0b4b2801 00000 LOOP
INFO:root:1632036003.0823636 m000002 m000002 6146e486db3de34f0b4b2813 00000 LOOP_MIX
```

---
