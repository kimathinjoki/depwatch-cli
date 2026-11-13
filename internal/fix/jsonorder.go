package fix

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// orderedObject is a JSON object that keeps its keys' order, so editing package.json changes only
// what the fix needs.
type orderedObject struct {
	keys   []string
	values map[string]json.RawMessage
	kids   map[string]*orderedObject
}

func (o *orderedObject) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("not an object")
	}
	o.values = map[string]json.RawMessage{}
	o.kids = map[string]*orderedObject{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		k := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		if _, seen := o.values[k]; !seen {
			o.keys = append(o.keys, k)
		}
		o.values[k] = v
	}
	return nil
}

func (o *orderedObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		if kid, ok := o.kids[k]; ok {
			vb, err := kid.MarshalJSON()
			if err != nil {
				return nil, err
			}
			b.Write(vb)
		} else {
			b.Write(o.values[k])
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// child returns the object under key, creating it (or replacing a non-object) at the end.
func (o *orderedObject) child(key string) *orderedObject {
	if o.kids == nil {
		o.kids = map[string]*orderedObject{}
		o.values = map[string]json.RawMessage{}
	}
	if kid, ok := o.kids[key]; ok {
		return kid
	}
	kid := &orderedObject{values: map[string]json.RawMessage{}, kids: map[string]*orderedObject{}}
	if raw, ok := o.values[key]; ok {
		if json.Unmarshal(raw, kid) != nil {
			kid = &orderedObject{values: map[string]json.RawMessage{}, kids: map[string]*orderedObject{}}
		}
	} else {
		o.keys = append(o.keys, key)
	}
	o.kids[key] = kid
	return kid
}

func (o *orderedObject) set(key, value string) {
	vb, _ := json.Marshal(value)
	if _, ok := o.values[key]; !ok {
		if _, kid := o.kids[key]; !kid {
			o.keys = append(o.keys, key)
		}
	}
	delete(o.kids, key)
	o.values[key] = vb
}
