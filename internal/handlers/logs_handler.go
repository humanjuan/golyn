package handlers

import (
	"bufio"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func GetLogs() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		log.Debug("GetLogs()")
		config := globals.GetConfig()
		var logFilePath string
		var typeLog string
		pageQuery := c.Query("page")
		pageSizeQuery := c.Query("pageSize")
		logLevelQuery := strings.ToUpper(c.Query("logLevel"))
		logTypeQuery := strings.ToLower(c.Query("logType"))
		logTimeQuery := strings.ToLower(c.Query("logTime"))

		switch logTypeQuery {
		case "db":
			logFilePath = filepath.Join(config.Log.Path, "/golyn_db.log")
			typeLog = "db"
		default:
			logFilePath = filepath.Join(config.Log.Path, "/golyn_server.log")
			typeLog = "server"
		}

		file, err := os.Open(logFilePath)
		if err != nil {
			log.Error("An error has occurred in the server when trying to open the log file. Try again later: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("an error has occurred in the server when trying to open the log file")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Error("An error has occurred in the server when trying to close the log file. Try again later: %v", err.Error())
				log.Sync()
			}
		}(file)

		counts := map[string]int{
			"INFO":     0,
			"ERROR":    0,
			"WARN":     0,
			"DEBUG":    0,
			"CRITICAL": 0,
		}
		var logs []string
		var fileLines []string
		var customLogTime time.Duration = 24 * time.Hour

		if logTimeQuery != "" {
			if strings.HasSuffix(logTimeQuery, "h") {
				logTimeInt, err := strconv.Atoi(strings.TrimSuffix(logTimeQuery, "h"))
				if err != nil {
					log.Error("An error has occurred in the server when trying to parse the logTime parameter. "+
						"Invalid logTime format. For hours, use a positive number followed by 'h'. %v", err.Error())
					log.Sync()

					err = fmt.Errorf("an error has occurred in the server when trying to parse the logTime parameter. " +
						"Invalid logTime format. For hours, use a positive number followed by 'h'")
					c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
					return
				}
				customLogTime = time.Duration(logTimeInt) * time.Hour
			} else if strings.HasSuffix(logTimeQuery, "m") {
				logTimeInt, err := strconv.Atoi(strings.TrimSuffix(logTimeQuery, "m"))
				if err != nil {
					log.Error("An error has occurred in the server when trying to parse the logTime parameter. "+
						"Invalid logTime format. For minutes, use a positive number followed by 'm'. %v", err.Error())
					log.Sync()
					err = fmt.Errorf("an error has occurred in the server when trying to parse the logTime parameter. " +
						"Invalid logTime format. For minutes, use a positive number followed by 'm'")
					c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
					return
				}
				customLogTime = time.Duration(logTimeInt) * time.Minute
			} else {
				log.Error("Invalid logTime format (%s). Use 'XXh' or 'XXm' for hour and minutes respectively", logTimeQuery)
				log.Sync()
				err = fmt.Errorf("invalid logTime format (%s). Use 'XXh' or 'XXm' for hour and minutes respectively", logTimeQuery)
				c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
				return
			}
		}

		now := time.Now()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			logTime, err := utils.ParseLogTimestamp(line)
			if err != nil || now.Sub(logTime) > customLogTime {
				continue
			}
			fileLines = append(fileLines, line)
		}

		if err := scanner.Err(); err != nil {
			log.Error("An error has occurred in the server when trying to read the log file: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("an error has occurred in the server when trying to read the log file")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		// Pagination setup
		isPaginated := pageQuery != "" || pageSizeQuery != ""
		page := 1
		pageSize := 10

		if isPaginated {
			page, err = strconv.Atoi(pageQuery)
			if err != nil || page < 1 {
				log.Error("An error has occurred in the server when trying to parse the page parameter: %v", err.Error())
				log.Sync()
				err = fmt.Errorf("an error has occurred in the server when trying to parse the page parameter")
				c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
				return
			}

			pageSize, err = strconv.Atoi(pageSizeQuery)
			if err != nil || pageSize < 1 {
				log.Error("An error has occurred in the server when trying to parse the pageSize parameter: %s", err.Error())
				log.Sync()
				err = fmt.Errorf("an error has occurred in the server when trying to parse the pageSize parameter")
				c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
				return
			}
		}

		totalLines := len(fileLines)
		totalPages := (totalLines + pageSize - 1) / pageSize

		// Reading in inverse order to pagination
		offset := (page - 1) * pageSize
		start := totalLines - offset - 1

		for i := start; i >= 0 && len(logs) < pageSize; i-- {
			line := fileLines[i]

			if logLevelQuery != "" && !utils.ContainsLogLevel(line, logLevelQuery) {
				continue
			}

			logs = append(logs, line)

			for level := range counts {
				if utils.ContainsLogLevel(line, level) {
					counts[level]++
					break
				}
			}
		}

		response := gin.H{
			"message":    utils.GetCodeMessage(http.StatusOK),
			"logs":       logs,
			"totalLines": totalLines,
			"totalPages": totalPages,
			"counts":     counts,
			"type":       typeLog,
		}

		if isPaginated {
			response["page"] = page
			response["pageSize"] = pageSize
			response["totalLogs"] = len(logs)
		}

		c.IndentedJSON(http.StatusOK, response)
	}
}
