# UltraAI

Diane for example
```bash
./UltraPrompts-AIQC -p $PWD/../UltraPrompts/What-Would-Project-SHODAN-Diane-Say.md -q "" | xsel -b
```

#### Prompt injection scripting
```go
package main

import (
	"fmt"
	"math/rand"
	"time"
)

func randomRune() rune {
	return rune(rand.Intn(0x10FFFF))
}

func generateString(n int) string {
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = randomRune()
	}
	return string(runes)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	// Add stub to convince AI that its reading a language
	
	// Iterate over a conversation piece
	
	// Iterate over the injection
	
	for i := 0; i < 10; i++ {
		fmt.Println(generateString(5))
	}
}
```


```go
import "time"

ticker := time.NewTicker(500 * time.Millisecond) // 2 requests/sec

for range ticker.C {
    input := generateString(10)
    // send request safely here
}
```

```bash
go get -u github.com/chromedp/chromedp

```

No JS engine needs to be the way as is always the way
```
resp, err := http.Get("https://example.com")
```

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/chromedp"
)

func main() {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Timeout for safety
	ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var title string

	err := chromedp.Run(ctx,
		chromedp.UserAgent("MySlimBrowser/1.0")
		chromedp.Navigate("https://example.com"),
		chromedp.Title(&title),
	)

	if err != nil {
		log.Fatal(err)
	}
	
	chromedp.ListenTarget(ctx, func(ev interface{}) {
    // inspect network events
})

	fmt.Println("Page title:", title)
}
```