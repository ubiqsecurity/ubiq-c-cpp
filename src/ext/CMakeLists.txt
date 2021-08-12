execute_process(
COMMAND mkdir "${CMAKE_BINARY_DIR}/fpe"
)

execute_process(
COMMAND ${CMAKE_COMMAND} "${CMAKE_CURRENT_SOURCE_DIR}/ubiq-fpe-c"
WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/fpe"
)

execute_process(
COMMAND ${CMAKE_COMMAND}  --build .
WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/fpe"
)


