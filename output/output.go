package output

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"net/http"
	"strings"
	"time"
)

var ConfFile map[string]interface{}
var elasticLock time.Time

func Output(index string, data interface{}){
	enableConsole := ConfFile["console"].(bool)
	enableFile := ConfFile["logfile"].(bool)
	enableElastic := ConfFile["elastic"].(bool)

	if enableFile {
		File(index, data)
	}
	if enableConsole {
		Console(index, data)
	}
	if enableElastic {
		Elastic(index, data)
	}
}

func Console(index string, data interface{}){

	console := log.New(os.Stdout, "",
		log.Ldate|log.Ltime|log.Lshortfile)
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Println(err)
	}
	console.Println(string(jsonData))
}

func File(index string, data interface{}){
	logPath := ConfFile["logpath"].(string)
	_ = os.MkdirAll(logPath, os.ModePerm)

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()

	path := fmt.Sprintf("%s/%s-%s.log",
		logPath, index, now.Format("20060102"))
	file, err := os.OpenFile(path,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	log.SetOutput(file)
	log.Println(string(jsonData))
}

func Elastic(index string, data interface{}){
	// Lock 避免死循環
	if time.Now().Sub(elasticLock) < 10 * time.Minute {
		return
	}

	// 所有格式轉成 JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err)
	}
	// JSON -> map[string]interface{}
	var dictData map[string]interface{}
	err = json.Unmarshal(jsonData, &dictData)
	if err != nil {
		fmt.Println(err)
	}
	// 添加 時間戳 & 主機名
	now := time.Unix(0, int64(dictData["Timestamp"].(float64)))
	dictData["@timestamp"] = now.UTC().Format(time.RFC3339Nano)
	dictData["hostname"], _ = os.Hostname()
	jsonData, err = json.Marshal(dictData)
	if err != nil {
		fmt.Println(err)
	}

	url := ConfFile["elastichost"].(string)
	url += fmt.Sprintf("/%s-%s/_doc",
			index, now.Format("2006.01.02"))
	content := "application/json"
	body := strings.NewReader(string(jsonData))
	resp, err := http.Post(url, content, body)
	if err != nil {
		fmt.Println(err)
		elasticLock = time.Now()
		return
	}
	defer resp.Body.Close()
	for _, v := range []int{200, 201, 203, 204} {
		if resp.StatusCode == v {
			return
		}
	}
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil{
		fmt.Println(err)
		return
	}
	fmt.Println(string(respData))
}