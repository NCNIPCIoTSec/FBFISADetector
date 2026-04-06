WORKSPACE=$(pwd)
SAMPLES_DIR=${WORKSPACE}/resources/samples
ARM_ELF_SAMPLE_PATH=${SAMPLES_DIR}/arm/p2im_drone.elf
OUTPUT_DIR=${WORKSPACE}/output/arm/bin/
ARM_BIN_SAMPLE_PATH=${WORKSPACE}/output/arm/bin/p2im_drone_0x8000000.bin

# 测试 FBFISADetector
cd ./src
echo "RUN => src/detectisa.py"
echo "[Test ARM Sample]"

echo "Execute => python detectisa.py -p -f ${ARM_ELF_SAMPLE_PATH}"
python detectisa.py -p -f ${ARM_ELF_SAMPLE_PATH}

echo "Execute => python detectisa.py -p -f ${ARM_BIN_SAMPLE_PATH}"
python elf2bin.py -f ${ARM_ELF_SAMPLE_PATH} -o ${OUTPUT_DIR}
python detectisa.py -p -f ${ARM_BIN_SAMPLE_PATH}


