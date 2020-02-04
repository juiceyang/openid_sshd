package main

func main() {
	go sshListenAndServe()
	httpListenAndServe()
}
