## Pass N - YYYY-MM-DD

### Scope
- `ExampleFamily`
- `ExampleClass`
- `ExampleClass::methodA`
- `ExampleClass::methodB`

### Changes
- Corrected helper prototypes to match the current function bodies.
- Reanalyzed touched functions and reread the most relevant callers.
- Renamed only the highest-signal locals after refreshing the locals table.

### What Worked
- Constructor, serializer, or small accessor evidence was enough to justify the applied types.
- Address-based targeting avoided overload ambiguity.

### What Didn't
- Inline decompile output was too small for the largest helper.
- Remaining locals were mostly spill state, not strong rename candidates.

### What Remains Opaque
- One or more trailing fields still need a stronger callsite before renaming.
- One branch still carries generic scratch state that is not yet worth forcing into names.

### Next Pass
- [ ] Recheck callers after propagation from the new prototypes.
- [ ] Only rename more locals if a stronger decompile or callsite appears.
- [ ] Save or checkpoint before moving to the next family.
