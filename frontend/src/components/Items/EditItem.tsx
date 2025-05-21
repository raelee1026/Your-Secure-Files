import {
  Button,
  ButtonGroup,
  DialogActionTrigger,
  Input,
  Text,
  VStack,
} from "@chakra-ui/react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { type SubmitHandler, useForm } from "react-hook-form"
import { FaExchangeAlt } from "react-icons/fa"

import { type ApiError, type ItemPublic, ItemsService } from "@/client"
import useCustomToast from "@/hooks/useCustomToast"
import { handleError } from "@/utils"
import {
  DialogBody,
  DialogCloseTrigger,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogRoot,
  DialogTitle,
  DialogTrigger,
} from "../ui/dialog"
import { Field } from "../ui/field"
import { getSessionKey } from "@/utils/aes"
import { encryptAESGCM } from "@/utils/aes"


interface EditItemProps {
  item: ItemPublic
}

interface ItemUpdateForm {
  title: string
  description?: string
}

const EditItem = ({ item }: EditItemProps) => {
  const [isOpen, setIsOpen] = useState(false)
  const queryClient = useQueryClient()
  const { showSuccessToast } = useCustomToast()
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<ItemUpdateForm>({
    mode: "onBlur",
    criteriaMode: "all",
    defaultValues: {
      ...item,
      description: item.description ?? undefined,
    },
  })

  const mutation = useMutation({
    mutationFn: (data: ItemUpdateForm) =>
      ItemsService.updateItem({ id: item.id, requestBody: data }),
    onSuccess: () => {
      showSuccessToast("Item updated successfully.")
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
  
  const onSubmit: SubmitHandler<ItemUpdateForm> = async (data) => {
  try {
    //  const username = localStorage.getItem("username")
    //   if (!username) throw new Error("Missing username")

    //   const password = localStorage.getItem("password")
    //   if (!password) throw new Error("Missing password")

    //   const privateKey = await decryptKmsPrivateKey(username, password); 
    //   console.log("privateKey", privateKey)
    //   if (!privateKey) throw new Error("Missing private key")
    //   await new Promise((resolve) => setTimeout(resolve, 500))

    //   const encryptedB64 = localStorage.getItem("session_key")!;
    //   console.log("encryptedB64", encryptedB64)
    //   if (!encryptedB64) throw new Error("Missing encrypted session key")
    //   await new Promise((resolve) => setTimeout(resolve, 500))

    //   const encryptedBytes = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));

    //   const rawKey = await crypto.subtle.decrypt(
    //     { name: "RSA-OAEP" },
    //     privateKey,
    //     encryptedBytes
    //   );
    //   console.log("rawKey", rawKey)
    //   if (!rawKey) throw new Error("Missing raw key")
    //   // stop for 5 seconds
    //   await new Promise((resolve) => setTimeout(resolve, 500))


    //   const aesKey = await crypto.subtle.importKey(
    //     "raw",
    //     rawKey,
    //     { name: "AES-GCM" },
    //     true,
    //     ["encrypt", "decrypt"]
    //   );
    //   console.log("aesKey", aesKey)
    //   if (!aesKey) throw new Error("Missing AES key")

    
    // const session_key_encrypted = localStorage.getItem("session_key");
    // if (!session_key_encrypted) throw new Error("Missing AES session key");

    const aesKey = await getSessionKey()
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
        <Button variant="ghost">
          <FaExchangeAlt fontSize="16px" />
          Edit Item
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit(onSubmit)}>
          <DialogHeader>
            <DialogTitle>Edit Item</DialogTitle>
          </DialogHeader>
          <DialogBody>
            <Text mb={4}>Update the item details below.</Text>
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
                    required: "Title is required",
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
            <ButtonGroup>
              <DialogActionTrigger asChild>
                <Button
                  variant="subtle"
                  colorPalette="gray"
                  disabled={isSubmitting}
                >
                  Cancel
                </Button>
              </DialogActionTrigger>
              <Button variant="solid" type="submit" loading={isSubmitting}>
                Save
              </Button>
            </ButtonGroup>
          </DialogFooter>
        </form>
        <DialogCloseTrigger />
      </DialogContent>
    </DialogRoot>
  )
}

export default EditItem
