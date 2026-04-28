# Wrapped locals JSON shape:
# {
#   "address": "0x...",
#   "function": "...",
#   "locals": [ ... ]
# }

# List index, local_id, display name, and type
jq -r '.locals[] | [.index, .local_id, .display_name, .type] | @tsv' /tmp/locals.json

# Show arguments only
jq -r '.locals[] | select(.is_arg) | [.index, .display_name, .type] | @tsv' /tmp/locals.json

# Show unnamed locals only
jq -r '.locals[] | select(.display_name | startswith("<unnamed_")) | [.index, .type] | @tsv' /tmp/locals.json

# Show one selected rename set by index
jq -r '.locals[] | select(.index==4 or .index==5 or .index==6 or .index==12) | [.index, .display_name, .type] | @tsv' /tmp/locals.json

# Show one selected rename set by current name
jq -r '.locals[] | select(.display_name=="v24" or .display_name=="v25" or .display_name=="v26") | [.index, .display_name, .type] | @tsv' /tmp/locals.json
