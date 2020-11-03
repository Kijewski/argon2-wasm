all:

.DELETE_ON_ERROR:

.SECONDARY:

.SECONDEXPANSION:

.PHONY: all clean


TARGETS := passwordhash

all: $(addprefix $(addprefix built/,${TARGETS}),.wasm .wasm.br .wasm.gz .native .js .js.br .js.gz)

all: $(addprefix $(addprefix built/,index),.html .html.br .html.gz)


SRC_passwordhash := argon2.cpp


CXXFLAGS_WASM := --target=wasm32

CXXFLAGS_DEBUG := -ggdb3 -grecord-gcc-switches

CXXFLAGS_SECURIY := -Werror=implicit-function-declaration -D_FORTIFY_SOURCE=2

CXXFLAGS_WARNINGS := -Wall -Wextra

CXXFLAGS_STD := -std=c++17 -fvisibility=hidden -emit-llvm -fno-common -ffunction-sections -fdata-sections

CXXFLAGS_OPTIMIZATION := -flto -O3


%/:
	mkdir -p "$@"


temp/%.cpp.wasm.bc: src/%.cpp | temp/
	clang++ \
		${CXXFLAGS_WASM} \
		${CXXFLAGS_DEBUG} \
		${CXXFLAGS_SECURIY} \
		${CXXFLAGS_WARNINGS} \
		${CXXFLAGS_STD} \
		${CXXFLAGS_OPTIMIZATION} \
		-c -o $@ $<


temp/%.cpp.native.bc: src/%.cpp | temp/
	clang++ \
		${CXXFLAGS_DEBUG} \
		${CXXFLAGS_SECURIY} \
		${CXXFLAGS_WARNINGS} \
		${CXXFLAGS_STD} \
		${CXXFLAGS_OPTIMIZATION} \
		-mtune=native -march=native -fPIC \
		-DGENKAT=1 \
		-c -o $@ $<


temp/%.combined.bc: temp/$${SRC_$$(firstword $$(subst ., ,$$*))}.$$(word 2,$$(subst ., ,$$*)).bc
	llvm-link -o $@ $^


temp/%.opt.bc: temp/%.combined.bc
	opt -O3 -o $@ $^


temp/%.wasm: temp/%.wasm.opt.bc
	wasm-ld \
		-O4 --no-entry --gc-sections --export-dynamic \
		--stack-first \
		-o $@ $^


temp/%.opt.wasm: temp/%.wasm | built/
	wasm-opt \
		-O4 --vacuum --debuginfo --disable-exception-handling \
		--mvp-features --detect-features --emit-target-features \
		--remove-unused-brs --simplify-locals --simplify-globals-optimizing \
		--dae-optimizing --reorder-functions --reorder-locals --merge-blocks --merge-locals \
		--dwarfdump -o $@ $< > $@.dwarf


built/%.wasm: temp/%.opt.wasm | built/
	wasm-opt --strip-dwarf -o $@ $<


temp/%.wasm.js: built/%.wasm | built/
	echo "const wasm_data_uri = 'data:application/wasm;base64,$$(base64 -w0 $<)';" > $@


built/%.gz: built/%
	zopfli -c $< > $@


built/%.br: built/%
	brotli -c $< > $@


built/%.native: temp/%.native.combined.bc | built/
	clang++ -O3 -fPIE -o $@ $<


built/passwordhash.js: temp/passwordhash.wasm.js src/passwordhash.js | built/
	./convert.sh $@ $^


built/%.html:  src/%.html | built/
	cp $< $@


clean:
	[ ! -d ./built/ ] || rm -r ./built/
	[ ! -d ./temp/ ] || rm -r ./temp/
