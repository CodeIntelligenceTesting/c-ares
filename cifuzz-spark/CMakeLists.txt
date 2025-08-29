# cifuzz:build-template:begin
# add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
# target_link_libraries({{ .FuzzTestName }} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,c-ci::cci_static>")
# target_compile_definitions({{ .FuzzTestName }} PRIVATE HAVE_CONFIG_H=1)
# target_include_directories({{ .FuzzTestName }}
#     PRIVATE "${PROJECT_BINARY_DIR}"
#             "${PROJECT_BINARY_DIR}/src/lib"
#             "${PROJECT_SOURCE_DIR}"
#             "${PROJECT_SOURCE_DIR}/src/lib"
#             "${PROJECT_SOURCE_DIR}/src/lib/include"
#             "${PROJECT_SOURCE_DIR}/include"
#             "${PROJECT_SOURCE_DIR}/test"
# )
# cifuzz:build-template:end
