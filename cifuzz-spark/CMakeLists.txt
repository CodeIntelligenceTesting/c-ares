# cifuzz:build-template:begin
# add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
# target_link_libraries({{ .FuzzTestName }} PRIVATE c-ares::cares_static caresinternal)
# cifuzz:build-template:end
