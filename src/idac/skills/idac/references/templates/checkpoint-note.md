## <target> - Recovery Pass <N> - <date>

### Scope
- `ExampleFamily`
- `ExampleClass`
- `ExampleClass::methodA`
- `ExampleClass::methodB`

### Types Recovered
- Added or refined recovered structs/classes/enums.
- Imported `headers/recovered/<target>.h` after preview.

### Prototypes Fixed
- Corrected helper prototypes to match the current function bodies.
- Reanalyzed touched functions and reread the most relevant callers.

### Locals Renamed Or Retyped
- Renamed only the highest-signal locals after refreshing the locals table.

### What Worked
- Constructor, serializer, or small accessor evidence was enough to justify the applied types.
- Address-based targeting avoided overload ambiguity.

### What Didn't Work
- Inline decompile output was too small for the largest helper.
- Remaining locals were mostly spill state, not strong rename candidates.

### Open Questions
- One or more trailing fields still need a stronger callsite before renaming.
- One branch still carries generic scratch state that is not yet worth forcing into names.

### TODO for Next Pass
- [ ] Recheck callers after propagation from the new prototypes.
- [ ] Only rename more locals if a stronger decompile or callsite appears.
- [ ] Save or checkpoint before moving to the next family.
