WORKSPACE=$(pwd)
SAMPLES_DIR=${WORKSPACE}/resources/samples
ARM_ELF_SAMPLE_PATH=${SAMPLES_DIR}/arm/p2im_gateway.elf
OUTPUT_DIR=${WORKSPACE}/output/arm/bin/
ARM_BIN_SAMPLE_PATH=${WORKSPACE}/output/arm/bin/p2im_gateway_0x8000000.bin

cd ./src/
python elf2bin.py -f ${ARM_ELF_SAMPLE_PATH} -o ${OUTPUT_DIR}

cd ./emulator/
python unicorn_run.py -f ${ARM_BIN_SAMPLE_PATH}
# python ghidra_emu_run.py




