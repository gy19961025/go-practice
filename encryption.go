package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
)

type fileEncryption struct {
	file       string
	md5        string
	sha1       string
	sha256     string
	isNotExist bool
}

// 编写hasher命令支持计算与globfomatpath匹配的所有文件的md5，sha1，sha256，并进行输出
// 注意：
// 0.命令格式 hasher --md5 --sha1 --sha256 globformatpath
// 1.文件大小不限，可以支持100G大小的文件计算
// 2. 输出：输出为表格形式每行一个文件信息，顺序为：文件路径（绝对路径），md5，sha1，sha256。需要输出表头信息（path，md5，sha1，sha256)，
//    列由命令行参数决定， 如hasher -md5 glob，只有文件路径和md5列。若无文件信息，输出表头和表体（表体内容输出-empty-）
// 3.在文件名中加入中文，尝试执行，表格是否对齐，查看tablewriter包如何使用，并解决中文对齐问题（https://github.com/olekukonko/tablewriter）

var fes []*fileEncryption

func (fe *fileEncryption) encryption(tp string, h func() hash.Hash) {
	hh := h()

	f, err := os.Open(fe.file)
	if err != nil {
		log.Fatal(err)
	} else {
		if _, err := io.Copy(hh, f); err == nil {
			switch tp {
			case "md5":
				fe.md5 = fmt.Sprintf("%x", hh.Sum(nil))
			case "sha1":
				fe.sha1 = fmt.Sprintf("%x", hh.Sum(nil))
			case "sha256":
				fe.sha256 = fmt.Sprintf("%x", hh.Sum(nil))
			}
			f.Close()
		} else {
			log.Fatal(err)
		}
	}
}

func sum(tps []string, file string) {
	var fe fileEncryption
	fe.file = file
	fe.isNotExist = false

	for _, tp := range tps {
		switch tp {
		case "md5":
			fe.encryption(tp, md5.New)
		case "sha1":
			fe.encryption(tp, sha1.New)
		case "sha256":
			fe.encryption(tp, sha256.New)
		}
	}
	fes = append(fes, &fe)
}

func main() {
	m := flag.Bool("md5", false, "md5")
	s1 := flag.Bool("sha1", false, "sha1")
	s256 := flag.Bool("sha256", false, "sha256")
	help := flag.Bool("h", false, "help")
	flag.Usage = func() {
		fmt.Println(`
Usage: hasher [--md5] [--sha1] [--sha256] filepath

Option:`)
		flag.PrintDefaults()
	}

	flag.Parse()
	options := make(map[string]bool)
	options["md5"] = *m
	options["sha1"] = *s1
	options["sha256"] = *s256

	files := flag.Args()

	if *help || len(files) == 0 || (*m == false && *s1 == false && *s256 == false) {
		flag.Usage()
	} else {
		var tableHeader = make([]string, 0)
		tableHeader = append(tableHeader, "path")
		for k, v := range options {
			if v {
				tableHeader = append(tableHeader, k)
			}
		}
		sort.Strings(tableHeader[1:])

		for _, file := range files {
			matches, err := filepath.Glob(file)
			if err != nil {
				log.Fatal(err)
			}
			if len(matches) == 0 {
				fes = append(fes, &fileEncryption{isNotExist: true})
			} else {
				for _, m := range matches {
					sum(tableHeader[1:], m)
				}
			}
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(tableHeader)

		datas := [][]string{}
		for _, fe := range fes {
			if fe.isNotExist == true {
				datas = append(datas, []string{"-empty-"})
				continue
			} else {
				file, _ := filepath.Abs(fe.file)
				data := []string{file}
				for _, header := range tableHeader[1:] {
					switch header {
					case "md5":
						data = append(data, fe.md5)
					case "sha1":
						data = append(data, fe.sha1)
					case "sha256":
						data = append(data, fe.sha256)
					}
				}
				datas = append(datas, data)
			}
		}
		table.AppendBulk(datas)
		table.Render()
	}
}
