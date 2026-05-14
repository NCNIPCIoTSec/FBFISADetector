export JAVA_HOME=/home/yq/workspace/tools/compilers/jdk-21.0.10+7

WORKSPACE=$(pwd)
SAMPLES_DIR=${WORKSPACE}/resources/samples

cd ./src

ARM_ELF_SAMPLE_PATH=${SAMPLES_DIR}/arm/p2im_gateway.elf
ARM_OUTPUT_DIR=${WORKSPACE}/output/arm/bin/
GHIDRA_ARM_ARCH="ARM:LE:32:Cortex"

echo "[架构] ARM"
echo "[样本] $ARM_ELF_SAMPLE_PATH"
echo "[模拟仿真] Extract ARM Binary Sample..."
ARM_BIN_SAMPLE_PATH=$(python elf2bin.py -f ${ARM_ELF_SAMPLE_PATH} -o ${ARM_OUTPUT_DIR} 2>&1 | grep "成功" | sed 's/.*<\/\([^>]*\)>.*/\1/')
echo "[抽取成功] ARM_BIN_SAMPLE_PATH: ${ARM_BIN_SAMPLE_PATH}"
echo "[测试样本] Test ARM Sample..."
python -m addrsolver.solvers -b ${ARM_BIN_SAMPLE_PATH} -v ${GHIDRA_ARM_ARCH} -r 4 -m "(0x365c, 0x368f)"

TRICORE_ELF_SAMPLE_PATH=/${SAMPLES_DIR}/tricore/ASCLIN_Shell_UART_1_KIT_TC297_TFT.elf
TRICORE_OUTPUT_DIR=${WORKSPACE}/output/tricore/bin/
GHIDRA_TRICORE_ARCH="tricore:LE:32:default"

echo "[架构] tricore"
echo "[样本] $TRICORE_ELF_SAMPLE_PATH"
echo "[模拟真实固件结构] Extract Tricore Binary Sample..."
TRICORE_BIN_SAMPLE_PATH=/$(python elf2bin.py -f ${TRICORE_ELF_SAMPLE_PATH} -o ${TRICORE_OUTPUT_DIR} 2>&1 | grep "成功" | sed 's/.*<\/\([^>]*\)>.*/\1/')
echo "[抽取成功] TRICORE_BIN_SAMPLE_PATH: ${TRICORE_BIN_SAMPLE_PATH}" 
echo "[测试仿真样本] Test Tricore Sample..."
python -m addrsolver.solvers -b ${TRICORE_BIN_SAMPLE_PATH} -v ${GHIDRA_TRICORE_ARCH} -r 4 -m "(0x0, 0x0)"

POWERPC_ELF_SAMPLE_PATH=${SAMPLES_DIR}/powerpc/0a2818b49cc0d364dc897328cc0d6e38.elf
POWERPC_OUTPUT_DIR=${WORKSPACE}/output/powerpc/bin/
GHIDRA_POWERPC_ARCH="PowerPC:BE:32:default"

echo "[架构] powerpc"
echo "[样本] $POWERPC_ELF_SAMPLE_PATH"
echo "[模拟真实固件结构] Extract PowerPC Binary Sample..."
POWERPC_BIN_SAMPLE_PATH=/$(python elf2bin.py -f ${POWERPC_ELF_SAMPLE_PATH} -o ${POWERPC_OUTPUT_DIR} 2>&1 | grep "成功" | sed 's/.*<\/\([^>]*\)>.*/\1/')
echo "[抽取成功] POWERPC_BIN_SAMPLE_PATH: ${POWERPC_BIN_SAMPLE_PATH}" 
echo "[测试仿真样本] Test PowerPC Sample..."
python -m addrsolver.solvers -b ${POWERPC_BIN_SAMPLE_PATH} -v ${GHIDRA_POWERPC_ARCH} -r 4 -m "(0x0, 0x0)"

MIPS_ELF_SAMPLE_PATH=${SAMPLES_DIR}/mips/0a890b8cfbfc4ec85d27cdb84e1924c5.elf
MIPS_OUTPUT_DIR=${WORKSPACE}/output/mips/bin/
GHIDRA_MIPS_ARCH="MIPS:BE:32:default"

echo "[架构] mips"
echo "[样本] $MIPS_ELF_SAMPLE_PATH"
echo "[模拟真实固件结构] Extract MIPS Binary Sample..."
MIPS_BIN_SAMPLE_PATH=/$(python elf2bin.py -f ${MIPS_ELF_SAMPLE_PATH} -o ${MIPS_OUTPUT_DIR} 2>&1 | grep "成功" | sed 's/.*<\/\([^>]*\)>.*/\1/')
echo "[抽取成功] MIPS_BIN_SAMPLE_PATH: ${MIPS_BIN_SAMPLE_PATH}" 
echo "[测试仿真样本] Test MIPS Sample..."
python -m addrsolver.solvers -b ${MIPS_BIN_SAMPLE_PATH} -v ${GHIDRA_MIPS_ARCH} -r 4 -m "(0x0, 0x0)"

echo "[测试完成]"
