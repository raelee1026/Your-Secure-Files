import { useMutation, useQueryClient } from "@tanstack/react-query"
import { type SubmitHandler, useForm } from "react-hook-form"
import { importAESKeyFromRawBytes } from "@/utils/aes"
import { decryptKmsPrivateKey, decryptWithPrivateKey } from "@/utils/crypto"

import { encryptAESGCM } from "@/utils/aes"

import {
  Button,
  DialogActionTrigger,
  DialogTitle,
  Input,
  Text,
  VStack,
} from "@chakra-ui/react"
import { useState } from "react"
import { FaPlus } from "react-icons/fa"

import { type ItemCreate, ItemsService } from "@/client"
import type { ApiError } from "@/client/core/ApiError"
import useCustomToast from "@/hooks/useCustomToast"
import { handleError } from "@/utils"
import {
  DialogBody,
  DialogCloseTrigger,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogRoot,
  DialogTrigger,
} from "../ui/dialog"
import { Field } from "../ui/field"

const AddItem = () => {
  const [isOpen, setIsOpen] = useState(false)
  const queryClient = useQueryClient()
  const { showSuccessToast } = useCustomToast()
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isValid, isSubmitting },
  } = useForm<ItemCreate>({
    mode: "onBlur",
    criteriaMode: "all",
    defaultValues: {
      title: "",
      description: "",
    },
  })

  const mutation = useMutation({
    mutationFn: (data: ItemCreate) =>
      ItemsService.createItem({ requestBody: data }),
    onSuccess: () => {
      showSuccessToast("Item created successfully.")
      reset()
      setIsOpen(false)
    },
    onError: (err: ApiError) => {
      handleError(err)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["items"] })
    },
  })

  const onSubmit: SubmitHandler<ItemCreate> = async (data) => {
    try {

        const username = localStorage.getItem("username")
        if (!username) throw new Error("Missing username")

        const password = localStorage.getItem("password")
        if (!password) throw new Error("Missing password")

        const privateKey = await decryptKmsPrivateKey(username, password); 
        console.log("privateKey", privateKey)
        if (!privateKey) throw new Error("Missing private key")
        await new Promise((resolve) => setTimeout(resolve, 500))

        const encryptedB64 = localStorage.getItem("session_key")!;
        console.log("encryptedB64", encryptedB64)
        if (!encryptedB64) throw new Error("Missing encrypted session key")
        await new Promise((resolve) => setTimeout(resolve, 500))

        const encryptedBytes = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));

        const rawKey = await crypto.subtle.decrypt(
          { name: "RSA-OAEP" },
          privateKey,
          encryptedBytes
        );
        console.log("rawKey", rawKey)
        if (!rawKey) throw new Error("Missing raw key")
        // stop for 5 seconds
        await new Promise((resolve) => setTimeout(resolve, 500))


        const aesKey = await crypto.subtle.importKey(
          "raw",
          rawKey,
          { name: "AES-GCM" },
          true,
          ["encrypt", "decrypt"]
        );
        console.log("aesKey", aesKey)
        if (!aesKey) throw new Error("Missing AES key")

      
      const session_key_encrypted = localStorage.getItem("session_key");
      if (!session_key_encrypted) throw new Error("Missing AES session key");

  
      const encryptedTitle = await encryptAESGCM(data.title, aesKey);
      const encryptedDescription = data.description
      ? await encryptAESGCM(data.description, aesKey)
      : "";

      mutation.mutate({
        title: encryptedTitle,
        description: encryptedDescription,
      });
    } catch (err) {
      console.error("❌ 加密失敗:", err);
    }
  };

  return (
    <DialogRoot
      size={{ base: "xs", md: "md" }}
      placement="center"
      open={isOpen}
      onOpenChange={({ open }) => setIsOpen(open)}
    >
      <DialogTrigger asChild>
        <Button value="add-item" my={4}>
          <FaPlus fontSize="16px" />
          Add Item
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit(onSubmit)}>
          <DialogHeader>
            <DialogTitle>Add Item</DialogTitle>
          </DialogHeader>
          <DialogBody>
            <Text mb={4}>Fill in the details to add a new item.</Text>
            <VStack gap={4}>
              <Field
                required
                invalid={!!errors.title}
                errorText={errors.title?.message}
                label="Title"
              >
                <Input
                  id="title"
                  {...register("title", {
                    required: "Title is required.",
                  })}
                  placeholder="Title"
                  type="text"
                />
              </Field>

              <Field
                invalid={!!errors.description}
                errorText={errors.description?.message}
                label="Description"
              >
                <Input
                  id="description"
                  {...register("description")}
                  placeholder="Description"
                  type="text"
                />
              </Field>
            </VStack>
          </DialogBody>

          <DialogFooter gap={2}>
            <DialogActionTrigger asChild>
              <Button
                variant="subtle"
                colorPalette="gray"
                disabled={isSubmitting}
              >
                Cancel
              </Button>
            </DialogActionTrigger>
            <Button
              variant="solid"
              type="submit"
              disabled={!isValid}
              loading={isSubmitting}
            >
              Save
            </Button>
          </DialogFooter>
        </form>
        <DialogCloseTrigger />
      </DialogContent>
    </DialogRoot>
  )
}

export default AddItem
