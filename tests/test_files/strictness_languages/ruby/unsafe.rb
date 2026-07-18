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
  
  User.where("id = #{params[:id]}")
end
