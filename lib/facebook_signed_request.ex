defmodule FacebookSignedRequest do
  @moduledoc """
  This module provides methods for checking the validity of a signed request
  and extracting the data out of it.
  """

  @doc """
  Checks if the signed request is valid or not.
  """
  def valid?(signed_request, app_secret) do
    {signature, payload} = split_signed_request(signed_request)
    check_signature(signature, payload, app_secret)
  end

  @doc """
  Extracts the data of the signed request.
  """
  def data(signed_request, app_secret) do
    {signature, payload} = split_signed_request(signed_request)
    valid? = check_signature(signature, payload, app_secret)

    if valid? do

      case Base.decode64(payload, padding: false) do
        {:ok, payload} -> Poison.decode(payload)
        _error         -> {:error, :base_64_decode_error}
      end

    else
      {:error, :invalid_request}
    end
  end

  defp check_signature(_signature, _payload, nil), do: false
  defp check_signature(signature, payload, secret) do
    sha256_hmac(payload, secret) == prepare_base64_url(signature)
  end

  defp split_signed_request(signed_request) do
    [signature | [payload | []]] = signed_request |> String.split(".")

    {signature, payload}
  end

  defp sha256_hmac(payload, app_secret) do
    :crypto.hmac(:sha256, app_secret, payload)
    |> Base.encode64()
    |> String.trim()
  end

  defp prepare_base64_url(str) do
    mode = str |> String.length |> rem(4)
    equal_signs = "=" |> String.duplicate(4 - mode)
    str <> equal_signs
    |> String.replace("-","+")
    |> String.replace("_","/")
  end
end
