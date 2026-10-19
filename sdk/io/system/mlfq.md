## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# mlfq

## 1. Role

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

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

### Related area

The scheduler is conceptually adjacent to the asynchronous I/O/server architecture but is not the same abstraction as the multiplexer itself.

## 6. References

### Related source

- `sdk/io/system/mlfq.hpp`
