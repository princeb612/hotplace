# mlfq

`mlfq.hpp` provides a multi-level feedback queue scheduling structure in the system I/O layer.

Its role is scheduling-oriented rather than network-protocol-specific. It can be used where work needs priority levels with feedback based on queue/service behavior.

```text
incoming work
     |
     v
  MLFQ queues
  +-------+
  | high  |
  +-------+
  | mid   |
  +-------+
  | low   |
  +-------+
```

## Related source

- `sdk/io/system/mlfq.hpp`

## Related area

The scheduler is conceptually adjacent to the asynchronous I/O/server architecture but is not the same abstraction as the multiplexer itself.
