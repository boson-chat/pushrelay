// Command pushrelay is the Boson push relay: a Web Push service that
// forwards to APNs and FCM.
package main

import "github.com/boson-chat/pushrelay/internal/commands"

func main() {
	commands.Execute()
}
