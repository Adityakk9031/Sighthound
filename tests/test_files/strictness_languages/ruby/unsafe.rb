require "shellwords"

def unsafe(params)
  system("sh -c #{params[:cmd]}") # Unsafe
  system "sh -c #{params[:cmd]}" # Unsafe
  exec("sh -c #{params[:cmd]}") # Unsafe
  spawn("sh -c #{params[:cmd]}") # Unsafe
  Open3.capture2("sh -c #{params[:cmd]}") # Unsafe
  IO.popen("sh -c #{params[:cmd]}") # Unsafe
  
  cmd = params[:cmd]
  system(cmd) # Unsafe (taint)
  system(*cmd) # Unsafe (taint)

  # Explicit shell executions with multiple arguments
  system("sh", "-c", params[:cmd]) # Unsafe (explicit shell)
  system("bash", "-c", params[:cmd]) # Unsafe (explicit shell)
  exec("sh", "-c", params[:cmd]) # Unsafe (explicit shell)
  spawn("sh", "-c", params[:cmd]) # Unsafe (explicit shell)

  # Explicit shell executions with env hash and options hash
  system({"ENV_VAR" => "val"}, "sh", "-c", params[:cmd]) # Unsafe (explicit shell with env hash)
  system("sh", "-c", params[:cmd], {chdir: "/tmp"}) # Unsafe (explicit shell with options hash)
  system({"ENV_VAR" => "val"}, "sh", "-c", params[:cmd], {chdir: "/tmp"}) # Unsafe (explicit shell with env and options hash)
  
  User.where("id = #{params[:id]}")
end
