import { useRef, useState } from "react"
import { Button }from "@/components/ui/button"  // ← 若是你客製化的 button
import { Text } from "@chakra-ui/react"
import { toaster } from "@/components/ui/toaster"
import { encryptFile } from "@/utils/crypto"
import { getSessionKey } from "@/utils/aes"
import { FaPlus } from "react-icons/fa"

const FileUpload = () => {
  const inputRef = useRef<HTMLInputElement | null>(null)
  const [file, setFile] = useState<File | null>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0]
    if (selected) {
      setFile(selected)
    }
  }

  const handleUpload = async () => {
    try {
      if (!file) throw new Error("No file selected.")

      const aesKey = await getSessionKey()
      const encryptedBlob = await encryptFile(file, aesKey)

      const formData = new FormData()
      formData.append("file", encryptedBlob, file.name)

      const response = await fetch("http://localhost:8000/api/v1/upload", {
        method: "POST",
        body: formData,
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token")}`,
        },
      })

      if (!response.ok) throw new Error("Upload failed.")

      toaster.create({
        type: "success",
        title: "Upload successful",
        description: `File "${file.name}" encrypted and uploaded.`,
      })

      setFile(null)
      if (inputRef.current) inputRef.current.value = ""
    } catch (err) {
      toaster.create({
        type: "error",
        title: "Upload failed",
        description: (err as Error).message,
      })
    }
  }

  return (
    <div className="flex flex-col items-start gap-4 mt-8">
      {/* Hidden file input */}
      <input
        type="file"
        ref={inputRef}
        className="hidden"
        onChange={handleFileChange}
      />

      <Button onClick={() => inputRef.current?.click()}>
        <FaPlus className="mr-2" />
        <span>Choose File</span>
      </Button>

      {file && <Text className="text-sm text-gray-600">Selected file: {file.name}</Text>}

      <Button className="bg-blue-600 hover:bg-blue-700 text-white" onClick={handleUpload}>
        Encrypt and Upload
      </Button>
    </div>
  )
}

export default FileUpload
