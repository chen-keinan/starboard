package compliance

//Spec represent the compliance specification
type Spec struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Controls    []Control `yaml:"controls"`
}

//Control represent the cps controls data and mapping checks
type Control struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Resources   []string `yaml:"resources"`
	Tool        string   `yaml:"tool"`
	Checks      []Check  `yaml:"checks"`
}

//Check represent the tool who perform the control check
type Check struct {
	ID string `yaml:"id"`
}
