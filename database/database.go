package database

import (
	"context"
	"errors"
	"reflect"
)

func (dbi *DBInstance) Select(query string, result interface{}, args ...interface{}) error {
	rows, err := dbi.db.Query(context.Background(), query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	v := reflect.ValueOf(result)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Slice {
		return errors.New("'result' must be a pointer to a slice")
	}

	elemType := v.Elem().Type().Elem()

	colMap := make(map[string]int)
	if elemType.Kind() == reflect.Struct {
		for i := 0; i < elemType.NumField(); i++ {
			tag := elemType.Field(i).Tag.Get("db")
			if tag != "" {
				colMap[tag] = i
			}
		}
	}

	fieldDescriptions := rows.FieldDescriptions()

	for rows.Next() {
		item := reflect.New(elemType).Elem()

		values := make([]interface{}, len(fieldDescriptions))
		for i, fd := range fieldDescriptions {
			colName := fd.Name
			if fieldIdx, ok := colMap[colName]; ok && elemType.Kind() == reflect.Struct {
				values[i] = item.Field(fieldIdx).Addr().Interface()
			} else if i == 0 && elemType.Kind() != reflect.Struct {
				values[i] = item.Addr().Interface()
			} else {
				var dummy interface{}
				values[i] = &dummy
			}
		}

		if err := rows.Scan(values...); err != nil {
			return err
		}

		v.Elem().Set(reflect.Append(v.Elem(), item))
	}

	return nil
}
