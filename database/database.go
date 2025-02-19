package database

import (
	"context"
	"errors"
	"reflect"
)

// improve this implementation (Select)

func (dbi *DBInstance) Select(query string, result interface{}, args ...interface{}) error {
	// Execute SQL query with optional arguments ($n)
	rows, err := dbi.db.Query(context.Background(), query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Check if 'result' is a pointer to struct or structs slice
	v := reflect.ValueOf(result)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Slice {
		return errors.New("'result' must be a pointer to a struct slice")
	}

	// Obtain type of element of the slice. Equivalent to reflect.TypeOf(Country{})
	elemType := v.Elem().Type().Elem()

	// Create an empty map for mapping column or field names in the structure
	colMap := make(map[string]int)
	for i := 0; i < elemType.NumField(); i++ {
		colName := elemType.Field(i).Tag.Get("db") // Column name in the database
		colMap[colName] = i
	}

	for rows.Next() {
		// Create a  new vale of struct. Is the same item := country{}
		item := reflect.New(elemType).Elem()

		// Create an interface for each column in the row
		values := make([]interface{}, len(colMap))
		for _, colIndex := range colMap {
			values[colIndex] = item.Field(colIndex).Addr().Interface()
		}

		if err := rows.Scan(values...); err != nil {
			return err
		}

		// Add the struct to result (slice of structures). V is a pointer to struct.
		v.Elem().Set(reflect.Append(v.Elem(), item))
	}

	return nil
}
