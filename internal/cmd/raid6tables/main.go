// Command raid6tables reimplements lib/raid6/mktables.c.
//
// Kbuild builds mktables as a hostprog and runs it to produce
// lib/raid6/tables.c:
//
//	cmd_mktable = $(obj)/mktables > $@
//
// RAID6 does not link without tables.o, so this is required for any config
// selecting CONFIG_RAID6_PQ rather than a follow-up nicety.
//
// This is a direct port. It has no inputs: the tables are computed from
// Galois-field arithmetic compiled into the program. The output is compared
// byte-for-byte against the upstream program's output; keep it that way, and
// prefer matching upstream's formatting over idiomatic Go when they conflict.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

func main() {
	out := flag.String("out", "", "Generated tables.c output")
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "raid6tables: %v\n", err)
		os.Exit(1)
	}
}

func run(outPath string) error {
	file, err := os.Create(outPath)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(file)
	writeTables(w)
	if err := w.Flush(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// gfmul multiplies in GF(2^8) with the RAID6 reduction polynomial 0x11d.
func gfmul(a, b uint8) uint8 {
	var v uint8
	for b != 0 {
		if b&1 != 0 {
			v ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return v
}

// gfpow raises a to the power b in GF(2^8).
func gfpow(a uint8, b int) uint8 {
	v := uint8(1)
	b %= 255
	if b < 0 {
		b += 255
	}
	for b != 0 {
		if b&1 != 0 {
			v = gfmul(v, a)
		}
		a = gfmul(a, a)
		b >>= 1
	}
	return v
}

func writeTables(w *bufio.Writer) {
	var exptbl, invtbl [256]uint8

	fmt.Fprintf(w, "#ifdef __KERNEL__\n")
	fmt.Fprintf(w, "#include <linux/export.h>\n")
	fmt.Fprintf(w, "#endif\n")
	fmt.Fprintf(w, "#include <linux/raid/pq.h>\n")

	// Multiplication table.
	fmt.Fprintf(w, "\nconst u8  __attribute__((aligned(256)))\nraid6_gfmul[256][256] =\n{\n")
	for i := 0; i < 256; i++ {
		fmt.Fprintf(w, "\t{\n")
		for j := 0; j < 256; j += 8 {
			fmt.Fprintf(w, "\t\t")
			for k := 0; k < 8; k++ {
				fmt.Fprintf(w, "0x%02x,%c", gfmul(uint8(i), uint8(j+k)), separator(k))
			}
		}
		fmt.Fprintf(w, "\t},\n")
	}
	writeExport(w, "raid6_gfmul")

	// Vector multiplication table.
	fmt.Fprintf(w, "\nconst u8  __attribute__((aligned(256)))\nraid6_vgfmul[256][32] =\n{\n")
	for i := 0; i < 256; i++ {
		fmt.Fprintf(w, "\t{\n")
		for j := 0; j < 16; j += 8 {
			fmt.Fprintf(w, "\t\t")
			for k := 0; k < 8; k++ {
				fmt.Fprintf(w, "0x%02x,%c", gfmul(uint8(i), uint8(j+k)), separator(k))
			}
		}
		for j := 0; j < 16; j += 8 {
			fmt.Fprintf(w, "\t\t")
			for k := 0; k < 8; k++ {
				fmt.Fprintf(w, "0x%02x,%c", gfmul(uint8(i), uint8((j+k)<<4)), separator(k))
			}
		}
		fmt.Fprintf(w, "\t},\n")
	}
	writeExport(w, "raid6_vgfmul")

	// Power-of-2 table (exponent).
	v := uint8(1)
	fmt.Fprintf(w, "\nconst u8 __attribute__((aligned(256)))\nraid6_gfexp[256] =\n{\n")
	for i := 0; i < 256; i += 8 {
		fmt.Fprintf(w, "\t")
		for j := 0; j < 8; j++ {
			exptbl[i+j] = v
			fmt.Fprintf(w, "0x%02x,%c", v, separator(j))
			v = gfmul(v, 2)
			if v == 1 {
				// Entry 255 is not a real entry.
				v = 0
			}
		}
	}
	writeExport(w, "raid6_gfexp")

	// Log-of-2 table.
	fmt.Fprintf(w, "\nconst u8 __attribute__((aligned(256)))\nraid6_gflog[256] =\n{\n")
	for i := 0; i < 256; i += 8 {
		fmt.Fprintf(w, "\t")
		for j := 0; j < 8; j++ {
			v = 255
			for k := 0; k < 256; k++ {
				if exptbl[k] == uint8(i+j) {
					v = uint8(k)
					break
				}
			}
			fmt.Fprintf(w, "0x%02x,%c", v, separator(j))
		}
	}
	writeExport(w, "raid6_gflog")

	// Inverse table, x^-1 == x^254.
	fmt.Fprintf(w, "\nconst u8 __attribute__((aligned(256)))\nraid6_gfinv[256] =\n{\n")
	for i := 0; i < 256; i += 8 {
		fmt.Fprintf(w, "\t")
		for j := 0; j < 8; j++ {
			v = gfpow(uint8(i+j), 254)
			invtbl[i+j] = v
			fmt.Fprintf(w, "0x%02x,%c", v, separator(j))
		}
	}
	writeExport(w, "raid6_gfinv")

	// inv(2^x + 1), the exponent-xor-inverse table.
	fmt.Fprintf(w, "\nconst u8 __attribute__((aligned(256)))\nraid6_gfexi[256] =\n{\n")
	for i := 0; i < 256; i += 8 {
		fmt.Fprintf(w, "\t")
		for j := 0; j < 8; j++ {
			fmt.Fprintf(w, "0x%02x,%c", invtbl[exptbl[i+j]^1], separator(j))
		}
	}
	writeExport(w, "raid6_gfexi")
}

// separator reproduces upstream's "(k == 7) ? '\n' : ' '": eight values per
// line, separated by spaces.
func separator(index int) rune {
	if index == 7 {
		return '\n'
	}
	return ' '
}

func writeExport(w *bufio.Writer, symbol string) {
	fmt.Fprintf(w, "};\n")
	fmt.Fprintf(w, "#ifdef __KERNEL__\n")
	fmt.Fprintf(w, "EXPORT_SYMBOL(%s);\n", symbol)
	fmt.Fprintf(w, "#endif\n")
}
