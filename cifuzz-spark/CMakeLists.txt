# cifuzz:build-template:begin
# add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
# target_link_libraries({{ .FuzzTestName }} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,c-ares::cares_static>")
# cifuzz:build-template:end
