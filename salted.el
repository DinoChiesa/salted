;;; salted.el --- functions for opening files encrypted with "salt_file"
;;
;; Copyright (c) 2019 Google LLC
;;
;; Author: Dino Chiesa
;; Version: 20191029
;; Created: Monday, 28 October 2019, 16:15
;; Url: https://github.com/DinoChiesa/salted
;;
;;; Commentary:
;;
;; Pretty simple: if you open a file with a name that ends
;; in .salted , this code will ask you for a passphrase and will decrypt the
;; file. Subsequent saves will re-encrypt the file.
;;
;; To use it, get the salt_file utility from
;; https://github.com/DinoChiesa/salted. Then put the following in your
;; ~/.emacs:
;;
;;      (require 'salted)
;;      (setq salted--salt-file-utility "~/location/of/salt_file")
;;
;; Then just use emacs as normal, to open a file with a .salted extension.
;;
;; NB: If you have "untabify" set in a before-save-hook, you need to remove or
;; disable it for buffers with .salted files; untabifying in the
;; before-save-hook can modify the ciphertext byte stream, which makes it
;; un-decryptable.
;;
;;; Bugs:
;;
;; - there is no function to save an existing file as "salted", eg `salted-save-file'
;;
;;; Code:


(defvar salted--salt-file-utility "~/bin/salt_file"
  "The location of the salt_file utilty to encrypt and decrypt. Set this to your specific location.")

(defvar salted--salt-file-passphrase ""
  "The passphrase for encrypting and decrypting")

(defvar salted--saved-position 0 "the position in the file before saving")

;; (defun salted-decrypt-file (passwd)
;;   "decrypt the file"
;;   (let ((coding-system-for-write 'no-conversion)
;;         (coding-system-for-read 'no-conversion))
;;     (call-process-region (point-min) (point-max) salted--salt-file-utility
;;                          t t nil "-in" buffer-file-name "-out" "-" "-passphrase" passwd "-decrypt")))

(defun salted-decrypt-buffer (passphrase)
  "decrypt the full buffer"
  (let ((coding-system-for-write 'raw-text) ;; no-conversion
        (coding-system-for-read 'raw-text)) ;; no-conversion
    (call-process-region (point-min) (point-max) salted--salt-file-utility
                         t t nil "-in" "-" "-out" "-" "-passphrase" passphrase "-decrypt")))

(defun salted-encrypt-buffer-to-file (passphrase)
  "encrypt the full buffer to a specific file"
  (message "encrypting to (%s)" buffer-file-name)

  (let ((coding-system-for-write 'no-conversion) ;; no-conversion
        (coding-system-for-read 'no-conversion) ;; no-conversion ;; utf-8-unix
        ;; ========
        ;; On Windows, I had some trouble directing the output to the
        ;; buffer and then decrypting. I did not have this problem on
        ;; MacOS.  This logic uses a temporary file to hold the output
        ;; from the program, then copies that file to the
        ;; `buffer-file-name'.
        (tmp-file (make-temp-file "salted-el-")))
    (message "using tmp-file (%s)" tmp-file)
    ;; if the encrypted data has a 0x09 (TAB) char, don't convert to spaces
    (setq indent-tabs-mode t)
    (call-process-region (point-min) (point-max) salted--salt-file-utility
                         t t nil "-in" "-" "-out" tmp-file "-passphrase" passphrase)
    ;; The file `tmp-file' now contains encrypted contents. Copy it to
    ;; the file identified by `buffer-file-name'.  Decryption will
    ;; happen later in the after-save-hook.
    (copy-file tmp-file buffer-file-name t)

    ;; need to revert the buffer here? not sure.
    (set-buffer-file-coding-system 'raw-text t) ;; no-conversion
    (revert-buffer t t t)
    (delete-file tmp-file)))


(define-generic-mode 'salted-file-mode
  (list ?#)
  nil nil
  '(".salted\\'")
  (list (lambda ()
          (add-hook 'before-save-hook
                    (lambda ()
                      (setq salted--saved-position (point))
                      (salted-encrypt-buffer-to-file salted--salt-file-passphrase))
                    nil t)

          (add-hook 'after-save-hook
                    (lambda ()
                      ;;(salted-decrypt-file salted--salt-file-passphrase)
                      (set-buffer-file-coding-system 'raw-text t) ;; no-conversion
                      (salted-decrypt-buffer salted--salt-file-passphrase)
                      (goto-char salted--saved-position)
                      (set-buffer-modified-p nil)
                      (auto-save-mode nil))
                    nil t)

          (set (make-local-variable 'salted--salt-file-passphrase) (read-passwd "passphrase: "))
          ;;(set (make-local-variable 'salted--salt-file-passphrase) (read-string "passphrase: "))
          ;; For a list of possible values of
          ;; CODING-SYSTEM, use M-x list-coding-systems.
          (set-buffer-file-coding-system 'raw-text t) ;; no-conversion

          ;; If you know exactly what coding system you want to use,
          ;; just set the variable ‘buffer-file-coding-system’ directly.

          (salted-decrypt-buffer salted--salt-file-passphrase)
          (goto-char (point-min))
          (set (make-local-variable 'salted--saved-position) (point))
          (auto-save-mode nil)
          (set-buffer-modified-p nil)))
  "Mode for salted encrypted files")

(provide 'salted)

;;; salted.el ends here
